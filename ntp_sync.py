"""
NTP 校时模块 — 使用授时中心 NTP 服务器获取标准时间

功能:
  1. 向授时中心 NTP 服务器查询标准时间（支持 IPv4 + IPv6）
     - 223.255.185.3 (IPv4)
     - 114.118.7.161 (IPv4)
     -  (IPv6)
  2. 最小延迟筛选（chrony 风格）：快速采样 8 次，只取延迟最小的一次
  3. 与本地系统时间比对，计算偏差
  4. 若偏差超过阈值，尝试校准系统时间
  5. 时钟漂移估算（RLS 递归最小二乘 + 遗忘因子 + 跳变保护）：
     用带指数遗忘的递归最小二乘在线估计频率漂移和瞬时偏差，
     每步计算量 O(p²)=4，零内存增长，自动适应时变漂移。
  6. 应用频率补偿（Windows: GetSystemTimeAdjustment + SetSystemTimeAdjustment, Linux: adjtimex）
  7. 系统时间步进校准（偏差超过阈值时）：
     Windows 先用 SetSystemTime（需要管理员 / SE_SYSTEMTIME 特权），失败回退系统校时命令
     w32tm /resync /force（必要时先启动 w32time 服务）；
     Linux 按系统上「实际安装的命令」依次尝试：
     chronyc makestep → ntpdate -u → sntp -S → timedatectl set-time →
     date -s @<epoch> → date -s "<本地时间>" → clock_settime(CLOCK_REALTIME)；
     每种方式执行后都回读系统时间，只有偏差真正降到容差以内才算校时成功。
"""

import os
import sys
import time
import struct
import socket
import asyncio
import logging
from typing import Optional, Tuple

from task_pool import run_ntp

logger = logging.getLogger("dns-proxy.ntp")

# 国家授时中心 NTP 服务器（IPv4 + IPv6 双栈）
NTP_SERVERS = [
    "223.255.185.3",
    "182.92.12.11",
    "203.107.6.88",
    "120.25.115.20",
    "114.118.7.161",
]

# NTP 端口
NTP_PORT = 123

# NTP 协议常量
NTP_PACKET_SIZE = 48
NTP_LI_VN_MODE = 0x1B  # LeapIndicator=0, Version=3, Mode=3 (Client)
NTP_TO_UNIX_EPOCH = 2208988800  # NTP 纪元(1900-01-01) 到 UNIX 纪元(1970-01-01) 的秒差

# 偏差阈值（秒）：超过此值则尝试校准系统时间
DEVIATION_THRESHOLD = 5.0

# NTP 查询超时（秒）
NTP_TIMEOUT = 5.0

# 时钟漂移估计参数（RLS）
DRIFT_SAMPLE_INTERVAL = 300       # 采样间隔（秒），与定时循环一致
RLS_LAMBDA = 0.98                 # 遗忘因子（0.95~0.995，越小适应越快）
MAX_JUMP = 1.0                    # 偏移跳变阈值（秒），超过预测值此幅度则跳过更新
RLS_MIN_SAMPLES = 3              # 至少 3 个样品才初次应用补偿
DRIFT_MIN_PPM = 1.0               # 低于此 PPM 不做补偿（噪声阈值）

# 频率补偿上限：真实晶振漂移一般不超过 ±100 PPM。估计值超过此上限说明 RLS 被
# NTP 采样噪声或系统时间跳变污染，此时若真的写入系统频率会主动把时钟带偏，
# 因此拒绝应用（只告警）。
DRIFT_MAX_PPM = 500.0

# 最小延迟筛选参数（chrony 风格）
NTP_MIN_DELAY_SAMPLES = 8         # 每次校时快速采样次数
NTP_MIN_DELAY_INTERVAL = 0.2      # 快速采样间隔（秒）


class DriftEstimator:
    """
    时钟漂移估计器（RLS 递归最小二乘 + 遗忘因子 + 跳变保护）。

    模型: offset = bias + drift * dt
    RLS 在线更新参数 [bias, drift]，每步只需 4 次乘加。
    λ=0.98 对应约 50 个采样的有效记忆长度，自动适应漂移变化。

    双重异常保护:
      1. 最小延迟筛选（chrony 风格）— 在 NTP 查询阶段完成
      2. 偏移跳变检测 — RLS 内部用 MAX_JUMP 保护

    使用:
        estimator = DriftEstimator()
        drift_ppm, offset_smooth = estimator.update(time.time(), offset)
    """

    def __init__(self, lam: float = RLS_LAMBDA):
        self._lam = lam
        self._t0: Optional[float] = None       # 第一次采样的时间
        self._theta: list = [0.0, 0.0]          # [bias(秒), drift(秒/秒)]
        self._P: list = [[1000.0, 0.0], [0.0, 1000.0]]  # 协方差矩阵
        self._sample_count: int = 0
        self._drift_ppm: float = 0.0
        self._offset_smoothed: float = 0.0

    @property
    def sample_count(self) -> int:
        return self._sample_count

    @property
    def drift_ppm(self) -> float:
        return self._drift_ppm

    @property
    def offset_smoothed(self) -> float:
        return self._offset_smoothed

    def _mat_vec_mul(self, mat: list, vec: list) -> list:
        return [mat[0][0] * vec[0] + mat[0][1] * vec[1],
                mat[1][0] * vec[0] + mat[1][1] * vec[1]]

    def _vec_inner(self, a: list, b: list) -> float:
        return a[0] * b[0] + a[1] * b[1]

    def _vec_scalar_mul(self, v: list, s: float) -> list:
        return [v[0] * s, v[1] * s]

    def _outer(self, a: list, b: list) -> list:
        return [[a[0] * b[0], a[0] * b[1]],
                [a[1] * b[0], a[1] * b[1]]]

    def _mat_sub(self, a: list, b: list) -> list:
        return [[a[0][0] - b[0][0], a[0][1] - b[0][1]],
                [a[1][0] - b[1][0], a[1][1] - b[1][1]]]

    def _mat_scalar_div(self, mat: list, s: float) -> list:
        return [[mat[0][0] / s, mat[0][1] / s],
                [mat[1][0] / s, mat[1][1] / s]]

    def update(self, local_time: float, offset: float) -> Tuple[float, float]:
        """
        RLS 在线更新：加入一个新采样，更新参数估计。

        内置偏移跳变保护：若 offset 与 RLS 一步预测值的偏差超过
        MAX_JUMP 秒，则跳过本次更新（防止 NTP 服务器异常将系统带偏）。

        Args:
            local_time: 本地系统时间（time.time() 返回值）
            offset: NTP 时间 - 本地时间（秒）

        Returns:
            (drift_ppm, offset_smoothed)
        """
        if self._t0 is None:
            self._t0 = local_time

        dt = local_time - self._t0
        x = [1.0, dt]
        self._sample_count += 1

        # RLS 一步预测
        y_pred = self._vec_inner(self._theta, x)

        # 偏移跳变检测：预测值 vs 实际测量
        # 首次采样 (sample_count==1) 时强制更新，防止初始偏差大时无限跳过
        if self._sample_count > 1:
            jump = abs(offset - y_pred)
            if jump > MAX_JUMP:
                logger.debug("RLS 跳过跳变: 预测=%.2f 秒, 实测=%.2f 秒, 跳变=%.2f 秒 (阈值=%.1f 秒)",
                             y_pred, offset, jump, MAX_JUMP)
                self._drift_ppm = self._theta[1] * 1_000_000
                self._offset_smoothed = y_pred
                return self._drift_ppm, self._offset_smoothed

        # RLS 核心：4 行矩阵更新
        residual = offset - y_pred
        Px = self._mat_vec_mul(self._P, x)
        denom = self._lam + self._vec_inner(x, Px)
        k = self._vec_scalar_mul(Px, 1.0 / denom)

        self._theta[0] += k[0] * residual
        self._theta[1] += k[1] * residual

        kxT_P = self._outer(k, self._mat_vec_mul(self._P, x))
        P_new = self._mat_sub(self._P, kxT_P)
        self._P = self._mat_scalar_div(P_new, self._lam)

        self._drift_ppm = self._theta[1] * 1_000_000
        self._offset_smoothed = self._vec_inner(self._theta, x)
        return self._drift_ppm, self._offset_smoothed


def _enable_systemtime_privilege() -> bool:
    """为当前进程令牌启用 SeSystemtimePrivilege（Windows 专用）。

    Windows 默认禁用该特权，SetSystemTime / SetSystemTimeAdjustment 之前必须显式启用。
    非提升（非管理员）进程的令牌里根本没有这条特权：AdjustTokenPrivileges 返回成功，
    但 GetLastError() 是 1300 (ERROR_NOT_ALL_ASSIGNED)，随后 API 调用就会得到
    1314 (ERROR_PRIVILEGE_NOT_HELD)。返回 True 表示确实已启用。
    """
    try:
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008
        SE_PRIVILEGE_ENABLED = 0x00000002

        # 注意：ctypes.wintypes 里没有 LUID（Python 3.11/3.13 均没有），必须自己定义。
        # 用 wintypes.LUID 会抛 AttributeError，特权永远启用不了 → 即使进程已提升，
        # SetSystemTimeAdjustment 也一定失败并返回 1314。
        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD),
                        ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID),
                        ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD),
                        ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        # 必须声明 argtypes/restype：GetCurrentProcess 返回的是 64 位伪句柄 (-1)，
        # 不声明 restype 时 ctypes 按 32 位 c_int 截断，OpenProcessToken 会拿到
        # 0x00000000FFFFFFFF 这个无效句柄而失败，导致特权永远启用不了
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                              ctypes.POINTER(wintypes.HANDLE)]
        advapi32.OpenProcessToken.restype = wintypes.BOOL
        advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                                   ctypes.POINTER(LUID)]
        advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
        advapi32.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL,
                                                   ctypes.c_void_p, wintypes.DWORD,
                                                   ctypes.c_void_p, ctypes.c_void_p]
        advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(token),
        ):
            logger.debug("OpenProcessToken 失败 (错误码: %d)", ctypes.get_last_error())
            return False
        try:
            luid = LUID()
            if not advapi32.LookupPrivilegeValueW(
                None, "SeSystemtimePrivilege", ctypes.byref(luid)
            ):
                logger.debug("LookupPrivilegeValueW 失败 (错误码: %d)", ctypes.get_last_error())
                return False
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            if not advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None):
                logger.debug("AdjustTokenPrivileges 调用失败 (错误码: %d)",
                             ctypes.get_last_error())
                return False
            # 只启用了部分特权时 AdjustTokenPrivileges 也返回 TRUE，
            # 必须查 GetLastError()：0 = 成功，1300 = 令牌里没有这条特权（进程未提升）
            err = ctypes.get_last_error()
            if err == 0:
                return True
            logger.debug("未能启用 SeSystemtimePrivilege (错误码: %d%s)", err,
                         "，令牌里没有这条特权（进程未提升）" if err == 1300 else "")
            return False
        finally:
            kernel32.CloseHandle(token)
    except Exception as e:
        logger.debug("启用 SE_SYSTEMTIME 特权失败: %s", e)
        return False


def _apply_drift_windows(drift_ppm: float) -> bool:
    """应用 Windows 时钟频率补偿（直接写入系统时钟速率）。

    正确用法（MSDN: SetSystemTimeAdjustment / GetSystemTimeAdjustment）：
      * lpTimeIncrement 由系统启动时固定（通常 156250 = 15.625ms，即每秒 64 次），
        必须用 GetSystemTimeAdjustment 读出，不能硬编码；
      * dwTimeAdjustment =「每个 lpTimeIncrement 周期加到系统时间上的 100ns 单位数」，
        正常值就是 lpTimeIncrement 本身；每偏离 1 个单位 ≈ 1e6/lpTimeIncrement PPM；
      * 因此 target = lpTimeIncrement * (1 + ppm/1e6)；
      * 参数顺序为 SetSystemTimeAdjustment(dwTimeAdjustment, bTimeAdjustmentDisabled)，
        第二个参数必须传 FALSE（TRUE 会让系统忽略调整值并自行同步）；
      * 调用者必须持有 SE_SYSTEMTIME 特权，非提升进程没有 → 1314。

    旧实现的参数顺序写反（把 TRUE/1 当成调整值），且基数硬编码 10000
    （真实 increment 是 156250），一旦以管理员身份运行会把时钟拖慢约 93%，此处修正。
    """
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        logger.debug("ctypes.windll 不可用，非 Windows 系统")
        return False

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetSystemTimeAdjustment.argtypes = [ctypes.POINTER(wintypes.DWORD),
                                                     ctypes.POINTER(wintypes.DWORD),
                                                     ctypes.POINTER(wintypes.BOOL)]
        kernel32.GetSystemTimeAdjustment.restype = wintypes.BOOL
        kernel32.SetSystemTimeAdjustment.argtypes = [wintypes.DWORD, wintypes.BOOL]
        kernel32.SetSystemTimeAdjustment.restype = wintypes.BOOL

        privilege_ok = _enable_systemtime_privilege()

        cur_adj = wintypes.DWORD(0)
        cur_inc = wintypes.DWORD(0)
        cur_disabled = wintypes.BOOL(True)
        if not kernel32.GetSystemTimeAdjustment(
            ctypes.byref(cur_adj), ctypes.byref(cur_inc), ctypes.byref(cur_disabled)
        ):
            logger.warning("读取系统时钟调整参数失败 (错误码: %d)", ctypes.get_last_error())
            return False

        increment = int(cur_inc.value) or 156250  # 兜底：典型 15.625ms
        # 限制在 ±10% 以内，防止参数写错把时钟带飞
        target = int(round(increment * (1.0 + drift_ppm / 1_000_000.0)))
        target = max(increment - increment // 10, min(increment + increment // 10, target))

        if not kernel32.SetSystemTimeAdjustment(wintypes.DWORD(target), False):
            err = ctypes.get_last_error()
            if err == 1314:
                logger.warning(
                    "Windows 频率补偿失败：当前进程没有 SE_SYSTEMTIME 特权 (1314)%s。"
                    "请以管理员身份运行程序，或给该账户授予“更改系统时间”权限后重新登录",
                    "" if privilege_ok else "（非提升进程无法获得该特权）"
                )
            else:
                logger.warning("Windows 频率补偿失败 (错误码: %d)", err)
            return False

        # 回读验证：bTimeAdjustmentDisabled 必须变成 FALSE 且调整值被接受才算生效
        new_adj = wintypes.DWORD(0)
        new_inc = wintypes.DWORD(0)
        new_disabled = wintypes.BOOL(True)
        applied = target
        if kernel32.GetSystemTimeAdjustment(
            ctypes.byref(new_adj), ctypes.byref(new_inc), ctypes.byref(new_disabled)
        ):
            if new_disabled.value:
                logger.warning("Windows 频率补偿未生效：系统仍处于“自行同步时间”状态")
                return False
            applied = int(new_adj.value)
            # 部分系统忽略低 4 位（16 个单位一组），故容差取 16
            if abs(applied - target) > 16:
                logger.warning("Windows 频率补偿未按预期生效：请求=%d 实际=%d (increment=%d)",
                               target, applied, increment)
                return False

        logger.info("Windows 频率补偿已应用: 漂移=%.2f PPM, 每 %d 个 100ns 周期调整 %d 个单位"
                    "（时钟速率已由本进程接管，Windows 时间服务不再自行纠正）",
                    drift_ppm, increment, applied)
        return True
    except Exception as e:
        logger.warning("Windows 频率补偿异常: %s", e)
        return False


def _apply_drift_linux(drift_ppm: float) -> bool:
    try:
        import ctypes
        import ctypes.util
        libc_path = ctypes.util.find_library("c")
        if not libc_path:
            logger.debug("找不到 libc")
            return False
        libc = ctypes.CDLL(libc_path, use_errno=True)

        class timex(ctypes.Structure):
            _fields_ = [
                ("modes", ctypes.c_uint),
                ("offset", ctypes.c_long),
                ("freq", ctypes.c_long),
                ("maxerror", ctypes.c_long),
                ("esterror", ctypes.c_long),
                ("status", ctypes.c_int),
                ("constant", ctypes.c_long),
                ("precision", ctypes.c_long),
                ("tolerance", ctypes.c_long),
            ]

        ADJ_FREQUENCY = 0x0002
        freq_val = int(drift_ppm * 65536)

        tx = timex()
        tx.modes = ADJ_FREQUENCY
        tx.freq = freq_val

        ret = libc.adjtimex(ctypes.byref(tx))
        if ret < 0:
            errno = ctypes.get_errno()
            if errno in (1, 13):  # EPERM / EACCES
                logger.warning(
                    "Linux 频率补偿失败：需要 root 或 CAP_SYS_TIME 权限 (errno=%d)。"
                    "若系统正在运行 chronyd/ntpd，时钟频率由该服务维护，本程序无需再补偿",
                    errno
                )
            else:
                logger.warning("Linux 频率补偿失败 (errno=%d)", errno)
            return False
        logger.info("Linux 频率补偿已应用: freq=%.2f PPM (adjtimex=%d)", drift_ppm, ret)
        return True
    except ImportError:
        logger.debug("ctypes 不可用")
        return False
    except Exception as e:
        logger.warning("Linux 频率补偿异常: %s", e)
        return False


def apply_drift_compensation(drift_ppm: float) -> bool:
    if abs(drift_ppm) < DRIFT_MIN_PPM:
        logger.debug("漂移 %.2f PPM 低于阈值 %.1f PPM，无需补偿", drift_ppm, DRIFT_MIN_PPM)
        return True
    if abs(drift_ppm) > DRIFT_MAX_PPM:
        logger.warning(
            "时钟漂移估计值 %.2f PPM 超出合理范围（±%.0f PPM），判定为 NTP 采样噪声"
            "或系统时间跳变污染，本次不写入系统频率（否则会主动把时钟带偏）",
            drift_ppm, DRIFT_MAX_PPM
        )
        return False
    logger.info("正在应用时钟频率补偿: %.2f PPM (%s)",
                drift_ppm, "偏快" if drift_ppm < 0 else "偏慢")
    if sys.platform == "win32":
        return _apply_drift_windows(drift_ppm)
    elif sys.platform.startswith("linux"):
        return _apply_drift_linux(drift_ppm)
    else:
        logger.warning("不支持在当前平台 %s 应用频率补偿", sys.platform)
        return False


def _is_ipv6(server: str) -> bool:
    return ":" in server


def _ntp_timestamp_to_unix(ntp_time: int, fraction: int) -> float:
    seconds = ntp_time - NTP_TO_UNIX_EPOCH
    fractional = fraction / (2 ** 32)
    return seconds + fractional


def _query_ntp_server(
    server: str, timeout: float = NTP_TIMEOUT
) -> Optional[Tuple[float, float, float]]:
    """
    向单个 NTP 服务器发送查询，返回 (UNIX 时间戳, 延迟秒数, 本地接收墙钟时刻)。

    自动识别 IPv4/IPv6 地址并创建对应类型的 socket。
    延迟 = 单调接收时刻 - 单调发送时刻（time.monotonic），用于最小延迟筛选。

    第三个返回值「收到应答那一刻的本地墙钟时间」是算偏差的唯一正确基准：
    采样可能因超时拖到几十秒，调用方若在采样结束后才取 time.time()，
    采样期间自然流逝的时间就会被误算成时钟偏差（实测可虚高 10 秒以上，
    进而把系统时间校偏十几秒）。

    Args:
        server: NTP 服务器 IP 地址（支持 IPv4 和 IPv6）
        timeout: 超时秒数

    Returns:
        (unix_timestamp, delay_seconds, local_recv_wall) 成功
        None 失败
    """
    sock = None
    try:
        if _is_ipv6(server):
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        packet = bytearray(NTP_PACKET_SIZE)
        packet[0] = NTP_LI_VN_MODE
        t_send = time.monotonic()

        if _is_ipv6(server):
            sock.sendto(packet, (server, NTP_PORT, 0, 0))
        else:
            sock.sendto(packet, (server, NTP_PORT))

        data, _ = sock.recvfrom(NTP_PACKET_SIZE * 2)
        t_recv = time.monotonic()
        t_recv_wall = time.time()   # 收到应答那一刻的本地墙钟时间（算偏差必须用它）
        sock.close()
        sock = None

        delay = t_recv - t_send

        if len(data) < 48:
            logger.debug("NTP 服务器 %s 返回数据过短: %d 字节", server, len(data))
            return None

        ntp_sec = struct.unpack("!I", data[40:44])[0]
        ntp_frac = struct.unpack("!I", data[44:48])[0]
        unix_time = _ntp_timestamp_to_unix(ntp_sec, ntp_frac)
        return unix_time, delay, t_recv_wall

    except socket.timeout:
        logger.debug("NTP 服务器 %s 超时", server)
        return None
    except OSError as e:
        logger.debug("NTP 服务器 %s 连接失败: %s", server, e)
        return None
    except Exception as e:
        logger.debug("NTP 服务器 %s 解析失败: %s", server, e)
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _get_ntp_time() -> Optional[Tuple[float, float]]:
    """（旧接口）依次查询所有服务器，返回 (UNIX 时间戳, 本地接收墙钟时刻)。"""
    for server in NTP_SERVERS:
        result = _query_ntp_server(server)
        if result is not None:
            unix_time, _, local_recv = result
            logger.debug("成功从 NTP 服务器 %s 获取标准时间", server)
            return unix_time, local_recv
    return None


def _get_ntp_time_min_delay() -> Optional[Tuple[float, float]]:
    """
    最小延迟采样（chrony 风格）：快速采样 NTP_MIN_DELAY_SAMPLES 次，
    只取延迟最小的那次结果。

    理论依据：最小延迟对应最接近真实时钟偏差（往返最为对称）。

    Returns:
        (延迟最小的 NTP UNIX 时间戳, 该次采样的本地接收墙钟时刻)，全部失败返回 None。
        必须连采样时刻一起返回：本函数按顺序遍历服务器，遇到超时会阻塞数秒到数十秒，
        若调用方用采样结束后的 time.time() 计算偏差，这段自然流逝会被误算成时钟偏差
        （实测虚高 10 秒以上，会把系统时间校偏十几秒）。
    """
    best_time = None
    best_delay = float("inf")
    best_local_recv = None

    for server in NTP_SERVERS:
        for _ in range(NTP_MIN_DELAY_SAMPLES):
            result = _query_ntp_server(server)
            if result is not None:
                unix_time, delay, local_recv = result
                if delay < best_delay:
                    best_delay = delay
                    best_time = unix_time
                    best_local_recv = local_recv
            time.sleep(NTP_MIN_DELAY_INTERVAL)
        if best_time is not None:
            logger.debug("最小延迟筛选: 服务器=%s, 延迟=%.1fms, 采样=%d次",
                         server, best_delay * 1000, NTP_MIN_DELAY_SAMPLES)
            return best_time, best_local_recv

    return None


# ======================== 外部命令执行 / 校时结果校验 ========================

def _run_command(args: list, timeout: float = 20.0) -> Tuple[int, str, str]:
    """执行外部命令，返回 (返回码, stdout, stderr)。

    命令不存在 / 超时 / 抛异常时统一返回 (-1, "", 原因)，不向上抛异常。
    """
    import subprocess

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
            creationflags=creationflags,
        )
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except FileNotFoundError:
        return -1, "", "命令不存在: %s" % args[0]
    except subprocess.TimeoutExpired:
        return -1, "", "命令超时(%.0fs): %s" % (timeout, " ".join(str(a) for a in args))
    except Exception as e:
        return -1, "", "命令执行异常: %s" % e


def _time_offset_vs(target_unix: float) -> float:
    """当前系统时间与目标时间的绝对偏差（秒）"""
    return abs(time.time() - target_unix)


def _verify_system_time(target_unix: float, tolerance: float = 1.0,
                        what: str = "校时") -> bool:
    """回读系统时间，确认校时是否真正生效（偏差 ≤ tolerance 秒）。

    只看命令返回码无法证明校时成功：权限不足、时间服务未运行、命令被接受
    但时钟未改动都会返回 0，因此必须回读系统时间做验证。
    """
    offset = _time_offset_vs(target_unix)
    if offset <= tolerance:
        logger.info("%s成功：系统时间已对齐（残余偏差 %.3f 秒 ≤ 容差 %.1f 秒）",
                    what, offset, tolerance)
        return True
    logger.warning("%s未生效：系统时间与 NTP 仍有 %.3f 秒偏差（容差 %.1f 秒）",
                   what, offset, tolerance)
    return False


# ======================== 系统校时（Windows） ========================

def _set_system_time_windows(unix_timestamp: float) -> bool:
    """把 Windows 系统时间设置为给定 UNIX 时间戳。

    两条路径，前一条失败才走后一条，每条执行后都回读系统时间验证：
      1. SetSystemTime()          需 SE_SYSTEMTIME 特权（管理员），毫秒级精确
      2. w32tm /resync /force     系统自带校时命令，走 Windows 时间服务
                                  （时间服务未启动时先 net start w32time）
    """
    if _set_system_time_windows_api(unix_timestamp):
        return True
    logger.info("SetSystemTime 未能校时，改用系统校时命令 w32tm /resync /force ...")
    return _sync_time_windows_w32tm(unix_timestamp)


def _set_system_time_windows_api(unix_timestamp: float) -> bool:
    """用 SetSystemTime() 设置系统时间（需要 SE_SYSTEMTIME 特权）。"""
    try:
        import ctypes
        from ctypes import wintypes
        from datetime import datetime, timezone

        dt = datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)

        class SYSTEMTIME(ctypes.Structure):
            _fields_ = [
                ("wYear", wintypes.WORD),
                ("wMonth", wintypes.WORD),
                ("wDayOfWeek", wintypes.WORD),
                ("wDay", wintypes.WORD),
                ("wHour", wintypes.WORD),
                ("wMinute", wintypes.WORD),
                ("wSecond", wintypes.WORD),
                ("wMilliseconds", wintypes.WORD),
            ]

        st = SYSTEMTIME()
        st.wYear = dt.year
        st.wMonth = dt.month
        st.wDayOfWeek = dt.weekday()
        st.wDay = dt.day
        st.wHour = dt.hour
        st.wMinute = dt.minute
        st.wSecond = dt.second
        st.wMilliseconds = dt.microsecond // 1000

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.SetSystemTime.argtypes = [ctypes.c_void_p]
        kernel32.SetSystemTime.restype = wintypes.BOOL

        # SetSystemTime 需要 SE_SYSTEMTIME 特权：Windows 默认禁用，需显式启用；
        # 非提升（非管理员）进程的令牌里根本没有该特权
        if not _enable_systemtime_privilege():
            logger.debug("未能启用 SE_SYSTEMTIME 特权（非提升进程），SetSystemTime 预计会失败")

        if not kernel32.SetSystemTime(ctypes.byref(st)):
            err = ctypes.get_last_error()
            if err == 1314:
                logger.warning(
                    "SetSystemTime 失败：当前进程没有“更改系统时间”特权 (1314)，"
                    "需以管理员身份运行程序（或给该账户授予该权限后重新登录）"
                )
            else:
                logger.warning("设置系统时间失败 (错误码: %d)", err)
            return False

        return _verify_system_time(unix_timestamp, tolerance=1.0, what="SetSystemTime 校时")

    except ImportError:
        logger.debug("ctypes.windll 不可用，非 Windows 系统")
        return False
    except Exception as e:
        logger.warning("设置系统时间异常: %s", e)
        return False


def _sync_time_windows_w32tm(unix_timestamp: float) -> bool:
    """执行系统校时命令 w32tm /resync /force（Windows 时间服务）。"""
    import shutil

    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    exe = shutil.which("w32tm") or os.path.join(system_root, "System32", "w32tm.exe")
    if not os.path.exists(exe):
        logger.warning("Windows 校时命令不可用：找不到 w32tm.exe")
        return False

    rc, out, err = _run_command([exe, "/resync", "/force"], timeout=30.0)
    text = (out + "\n" + err).strip()

    # 时间服务未启动（0x80070426 / 1058）：先启动服务再重试一次
    if rc != 0 and any(k in text for k in
                       ("0x80070426", "1058", "has not been started", "未启动")):
        net_exe = shutil.which("net") or os.path.join(system_root, "System32", "net.exe")
        logger.info("Windows 时间服务(w32time)未启动，尝试启动...")
        src_rc, src_out, src_err = _run_command([net_exe, "start", "w32time"], timeout=20.0)
        if src_rc == 0:
            rc, out, err = _run_command([exe, "/resync", "/force"], timeout=30.0)
            text = (out + "\n" + err).strip()
        else:
            logger.warning("启动 Windows 时间服务失败: %s",
                           (src_out + " " + src_err).strip()[:200])

    if rc != 0:
        if any(k in text for k in ("1314", "0x80070005", "Access is denied", "拒绝访问")):
            logger.warning(
                "w32tm /resync 失败：权限不足（需要管理员 / SE_SYSTEMTIME 特权）。"
                "请以管理员身份运行程序，或用计划任务以 SYSTEM 账户执行 w32tm /resync /force"
            )
        else:
            logger.warning("w32tm /resync 失败 (返回码 %d): %s", rc, text[:300] or "无输出")
        return False

    logger.info("w32tm /resync 命令执行成功: %s", text[:200] or "无输出")
    if _verify_system_time(unix_timestamp, tolerance=2.0, what="w32tm 校时"):
        return True
    # w32time 使用其自身配置的时间源，与本次测得的授时中心时间可能略有出入
    logger.warning("w32tm 已成功执行，但系统时间与本次测得的 NTP 时间仍不一致"
                   "（w32time 使用其自身配置的时间源，属正常现象）")
    return True


# ======================== 系统校时（Linux） ========================

def _linux_chronyc_makestep() -> Tuple[bool, str]:
    """chronyc makestep：让 chrony 立即步进校时（要求 chronyd 在运行且已选定时间源）。"""
    rc, out, err = _run_command(["chronyc", "makestep"], timeout=15.0)
    if rc != 0:
        return False, (err or out or "chronyc 返回码 %d" % rc)[:200]
    if "200 OK" not in (out + err):
        return False, "chronyc 输出: %s" % (out or err)[:160]
    return True, "chronyc makestep -> %s" % out[:120]


def _linux_ntpdate() -> Tuple[bool, str]:
    """ntpdate -u <server>：传统校时命令（系统安装了 ntpdate 时可用）。"""
    last = ""
    for server in NTP_SERVERS[:3]:
        rc, out, err = _run_command(["ntpdate", "-u", "-t", "5", server], timeout=20.0)
        last = (out + " " + err).strip()
        if rc == 0:
            return True, "ntpdate %s -> %s" % (server, last[:120])
    return False, (last or "ntpdate 所有服务器均失败")[:200]


def _linux_sntp() -> Tuple[bool, str]:
    """sntp -S <server>：ntp 包自带，-S 表示立即步进校时。"""
    last = ""
    for server in NTP_SERVERS[:3]:
        rc, out, err = _run_command(["sntp", "-S", server], timeout=20.0)
        last = (out + " " + err).strip()
        if rc == 0:
            return True, "sntp -S %s -> %s" % (server, last[:120])
    return False, (last or "sntp 所有服务器均失败")[:200]


def _linux_timedatectl(local_str: str) -> Tuple[bool, str]:
    """timedatectl set-time：入参必须是「本地时间」字符串（按系统时区解释），
    且需先关闭自动同步，否则 set-time 会被拒绝。"""
    rc, out, err = _run_command(["timedatectl", "set-ntp", "false"], timeout=15.0)
    if rc != 0:
        logger.debug("timedatectl set-ntp false 未成功（可能本就没启用自动同步）: %s",
                     (out + " " + err).strip()[:160])
    rc, out, err = _run_command(["timedatectl", "set-time", local_str], timeout=15.0)
    if rc != 0:
        return False, (out + " " + err).strip()[:200]
    return True, "timedatectl set-time %s" % local_str


def _linux_date_epoch(unix_timestamp: float) -> Tuple[bool, str]:
    """GNU date：date -s @<epoch> 直接按 UTC 设定（busybox/BSD date 不支持该语法）。"""
    rc, out, err = _run_command(["date", "-s", "@%d" % int(unix_timestamp)], timeout=15.0)
    if rc != 0:
        return False, (out + " " + err).strip()[:200]
    return True, out[:120]


def _linux_date_local(local_str: str) -> Tuple[bool, str]:
    """busybox / BSD date：date -s "<本地时间>"（按系统时区解释）。"""
    rc, out, err = _run_command(["date", "-s", local_str], timeout=15.0)
    if rc != 0:
        return False, (out + " " + err).strip()[:200]
    return True, out[:120]


def _linux_clock_settime(unix_timestamp: float) -> Tuple[bool, str]:
    """直接调用 libc 的 clock_settime(CLOCK_REALTIME)：不依赖任何外部命令，
    需要 root 或 CAP_SYS_TIME。"""
    try:
        import ctypes
        import ctypes.util
    except ImportError:
        return False, "ctypes 不可用"

    libc_path = ctypes.util.find_library("c") or "libc.so.6"
    libc = ctypes.CDLL(libc_path, use_errno=True)

    class timespec(ctypes.Structure):
        _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]

    CLOCK_REALTIME = 0
    whole = int(unix_timestamp)
    ts = timespec()
    ts.tv_sec = whole
    ts.tv_nsec = int(round((unix_timestamp - whole) * 1e9))
    if ts.tv_nsec >= 1000000000:
        ts.tv_sec += 1
        ts.tv_nsec -= 1000000000

    if libc.clock_settime(ctypes.c_int(CLOCK_REALTIME), ctypes.byref(ts)) != 0:
        return False, "clock_settime 失败 (errno=%d)" % ctypes.get_errno()
    return True, "clock_settime(CLOCK_REALTIME) OK"


def _set_system_time_linux(unix_timestamp: float) -> bool:
    """把 Linux 系统时间设置为给定 UNIX 时间戳。

    按系统上「实际安装的命令」依次尝试（shutil.which 探测），每种方式执行后
    都回读系统时间验证，只有偏差真正降到 1 秒以内才算校时成功：
      1. chronyc makestep        装了 chrony 时最正确：时钟由 chrony 维护
      2. ntpdate -u <server>     传统校时命令
      3. sntp -S <server>        ntp 包自带
      4. timedatectl set-time    systemd 环境（先 set-ntp false）
      5. date -s @<epoch>        GNU coreutils，按 UTC 直接设定
      6. date -s "<本地时间>"      busybox / BSD date
      7. clock_settime()         无命令可用时直接调 libc（root / CAP_SYS_TIME）
    """
    import shutil

    local_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(unix_timestamp))

    methods = []
    if shutil.which("chronyc"):
        methods.append(("chronyc makestep", _linux_chronyc_makestep))
    if shutil.which("ntpdate"):
        methods.append(("ntpdate -u", _linux_ntpdate))
    if shutil.which("sntp"):
        methods.append(("sntp -S", _linux_sntp))
    if shutil.which("timedatectl"):
        methods.append(("timedatectl set-time", lambda: _linux_timedatectl(local_str)))
    if shutil.which("date"):
        methods.append(("date -s @%d" % int(unix_timestamp),
                        lambda: _linux_date_epoch(unix_timestamp)))
        methods.append(('date -s "%s"' % local_str,
                        lambda: _linux_date_local(local_str)))
    methods.append(("clock_settime(CLOCK_REALTIME)",
                    lambda: _linux_clock_settime(unix_timestamp)))

    logger.info("Linux 校时命令探测结果：%s", ", ".join(name for name, _ in methods))
    for name, func in methods:
        try:
            ok, detail = func()
        except Exception as e:
            ok, detail = False, "异常: %s" % e
        if not ok:
            logger.debug("校时方式 %s 执行失败：%s", name, detail)
            continue
        if _verify_system_time(unix_timestamp, tolerance=1.0, what="%s 校时" % name):
            return True
        logger.debug("校时方式 %s 返回成功但系统时间未改变：%s", name, detail)

    logger.warning(
        "系统校时失败：已依次尝试 %s，系统时间仍未对齐。通常需要 root/CAP_SYS_TIME 权限，"
        "或系统 NTP 服务(chronyd/ntpd/systemd-timesyncd)正在接管时钟",
        ", ".join(name for name, _ in methods)
    )
    return False


def check_system_time_vs_ntp(min_delay: bool = True) -> Tuple[bool, float]:
    """
    查询 NTP 标准时间，与本地时间比对，必要时校准系统时间。

    默认启用 chrony 风格的最小延迟筛选。

    Args:
        min_delay: 是否启用最小延迟筛选（默认 True）

    流程:
      1. 依次查询国家授时中心 NTP 服务器
         - min_delay=True: 每台快速采 8 次，取延迟最小的结果
         - min_delay=False: 每台只查一次
      2. 计算 NTP 时间与本地系统时间的偏差
      3. 若偏差超过阈值（DEVIATION_THRESHOLD），尝试校准
      4. 若所有 NTP 服务器均无响应，记录 error

    Returns:
        (success, offset_seconds)
    """
    logger.info("正在通过国家授时中心 NTP 服务器校时%s...",
                "（最小延迟筛选）" if min_delay else "")

    if min_delay:
        sample = _get_ntp_time_min_delay()
    else:
        sample = _get_ntp_time()

    if sample is None:
        logger.error(
            "NTP 校时失败：无法连接国家授时中心服务器 %s（端口 %d），"
            "所有服务器均无响应。系统时间可能不准确，证书验证将使用当前系统时间。",
            ", ".join(NTP_SERVERS), NTP_PORT
        )
        return False, 0.0

    ntp_time, local_at_sample = sample
    # 偏差必须用「收到 NTP 应答那一刻」的本地时间计算；采样（含超时重试）本身
    # 可能耗时数十秒，用结束后的 time.time() 会把这段流逝误算成时钟偏差
    offset = ntp_time - local_at_sample
    elapsed = time.time() - local_at_sample

    ntp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ntp_time))
    local_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(local_at_sample))

    if abs(offset) <= DEVIATION_THRESHOLD:
        logger.info(
            "NTP 校时通过：NTP=%s，本地=%s，偏差=%.2f 秒（阈值 %d 秒，采样耗时 %.1f 秒）",
            ntp_str, local_str, offset, DEVIATION_THRESHOLD, elapsed
        )
        return True, offset

    logger.warning(
        "系统时间偏差 %.2f 秒（超过阈值 %d 秒）：NTP=%s，本地=%s。尝试校准系统时间...",
        offset, DEVIATION_THRESHOLD, ntp_str, local_str
    )

    # 采样到设置之间存在时间流逝，必须把 NTP 时间外推到「现在」再写入，
    # 否则会把系统时间设成若干秒之前的旧值
    target = ntp_time + elapsed

    if sys.platform == "win32":
        calibrated = _set_system_time_windows(target)
    elif sys.platform.startswith("linux"):
        calibrated = _set_system_time_linux(target)
    else:
        logger.warning("不支持在当前平台 %s 自动校准系统时间", sys.platform)
        calibrated = False

    if not calibrated:
        logger.warning(
            "系统时间校准失败（偏差 %.2f 秒）。证书验证将使用当前（可能不准确）的系统时间，"
            "若遇到证书验证错误，请手动校准系统时间。",
            offset
        )

    return True, offset



# ======================== 异步接口 ========================

async def query_ntp_server_async(server: str, timeout: float = NTP_TIMEOUT,
                                  loop=None) -> Optional[Tuple[float, float, float]]:
    """异步查询单个 NTP 服务器（走 NTP 专属线程池，不与 DNS 查询排队）"""
    if loop is None:
        loop = asyncio.get_event_loop()
    return await run_ntp(_query_ntp_server, server, timeout)


async def _query_server_best(
    server: str, min_delay: bool
) -> Optional[Tuple[float, float, float]]:
    """查询单台服务器多次（如果启用 min_delay），返回
    (best_time, best_delay, local_recv)：第三个是「收到应答那一刻的本地墙钟时间」"""
    samples = NTP_MIN_DELAY_SAMPLES if min_delay else 1
    best_time = None
    best_delay = float("inf")
    best_local_recv = None
    for _ in range(samples):
        result = await query_ntp_server_async(server)
        if result is not None:
            unix_time, delay, local_recv = result
            if delay < best_delay:
                best_delay = delay
                best_time = unix_time
                best_local_recv = local_recv
        await asyncio.sleep(NTP_MIN_DELAY_INTERVAL if min_delay else 0)
    if best_time is not None:
        return best_time, best_delay, best_local_recv
    return None


async def get_ntp_time_async(min_delay: bool = True) -> Optional[Tuple[float, float]]:
    """
    异步并行查询所有 NTP 服务器，取最快返回的结果。
    支持最小延迟筛选：每台快速采样 NTP_MIN_DELAY_SAMPLES 次。
    使用 asyncio.wait(FIRST_COMPLETED) 及时返回，不等待慢速服务器超时。

    Returns:
        (NTP UNIX 时间戳, 收到该应答时的本地墙钟时刻)，全部失败返回 None。
        第二个值是算偏差的基准：即使并行查询很快，调用方也不该用采样结束后的
        time.time() 代替它。
    """
    tasks = [asyncio.create_task(_query_server_best(server, min_delay)) for server in NTP_SERVERS]
    if not tasks:
        return None

    # 总超时兜底：30 秒后不再等待
    TOTAL_TIMEOUT = 30.0
    best_time = None
    best_delay = float("inf")
    best_local_recv = None
    pending = set(tasks)
    deadline = asyncio.get_event_loop().time() + TOTAL_TIMEOUT

    while pending:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            break
        try:
            done, pending = await asyncio.wait(
                pending, timeout=remaining, return_when=asyncio.FIRST_COMPLETED
            )
        except asyncio.TimeoutError:
            break

        for task in done:
            try:
                result = task.result()
            except (asyncio.CancelledError, Exception):
                continue
            if result is not None and isinstance(result, tuple) and len(result) == 3:
                unix_time, delay, local_recv = result
                if delay < best_delay:
                    best_delay = delay
                    best_time = unix_time
                    best_local_recv = local_recv

        # 已找到有效结果，取消剩余任务
        if best_time is not None:
            for t in pending:
                t.cancel()
            break

    # 取消所有仍在 pending 的任务
    for t in pending:
        t.cancel()

    if best_time is not None:
        logger.debug("异步并行NTP: 最小延迟=%.1fms (最快服务器返回)", best_delay * 1000)
        return best_time, best_local_recv
    return None


async def check_system_time_vs_ntp_async(freeze_event: asyncio.Event = None,
                                          min_delay: bool = True) -> Tuple[bool, float]:
    """
    异步 NTP 校时（支持冻结/恢复）。

    与 check_system_time_vs_ntp 功能相同，但不阻塞事件循环。

    Args:
        freeze_event: 冻结事件。set() 时循环暂停，clear() 时恢复。
        min_delay: 是否启用最小延迟筛选。

    Returns:
        (success, offset_seconds)
    """
    logger_n = logging.getLogger("dns-proxy.ntp")

    # 检查冻结状态：持续等待直到未冻结
    if freeze_event is not None:
        while freeze_event.is_set():
            await asyncio.sleep(1)

    logger_n.info("正在异步 NTP 校时%s...", "（最小延迟筛选）" if min_delay else "")

    sample = await get_ntp_time_async(min_delay=min_delay)

    if sample is None:
        logger_n.error(
            "NTP 校时失败：无法连接授时中心服务器 %s（端口 %d）",
            ", ".join(NTP_SERVERS), NTP_PORT
        )
        return False, 0.0

    ntp_time, local_at_sample = sample
    # 偏差基准必须是「收到 NTP 应答那一刻」的本地时间，而不是采样结束后的
    # time.time()——后者会把采样期间自然流逝的时间误算成时钟偏差
    offset = ntp_time - local_at_sample
    elapsed = time.time() - local_at_sample

    ntp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ntp_time))
    local_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(local_at_sample))

    if abs(offset) <= DEVIATION_THRESHOLD:
        logger_n.info(
            "NTP 校时通过：NTP=%s，本地=%s，偏差=%.2f 秒（阈值 %d 秒，采样耗时 %.1f 秒）",
            ntp_str, local_str, offset, DEVIATION_THRESHOLD, elapsed
        )
        return True, offset

    logger_n.warning(
        "系统时间偏差 %.2f 秒（超过阈值 %d 秒）：NTP=%s，本地=%s。尝试校准系统时间...",
        offset, DEVIATION_THRESHOLD, ntp_str, local_str
    )

    # 采样到设置之间有流逝，必须把 NTP 时间外推到「现在」再写入，
    # 否则系统会被设成若干秒之前的旧值
    target = ntp_time + elapsed

    loop = asyncio.get_event_loop()
    if sys.platform == "win32":
        calibrated = await run_ntp(_set_system_time_windows, target)
    elif sys.platform.startswith("linux"):
        # 校时按顺序执行外部命令并回读验证，可能耗时数十秒，必须放到线程池，
        # 否则会阻塞事件循环、导致本地 DNS 服务在此期间无响应
        calibrated = await run_ntp(_set_system_time_linux, target)
    else:
        calibrated = False

    if not calibrated:
        logger_n.warning(
            "系统时间校准失败（偏差 %.2f 秒）。证书验证将使用当前（可能不准确）的系统时间，"
            "若遇到证书验证错误，请手动校准系统时间",
            offset
        )

    return True, offset

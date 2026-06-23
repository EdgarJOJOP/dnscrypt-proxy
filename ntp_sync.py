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
  6. 应用频率补偿（Windows: SetSystemTimeAdjustment, Linux: adjtimex）
"""

import os
import sys
import time
import struct
import socket
import asyncio
import logging
from typing import Optional, Tuple

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


def _apply_drift_windows(drift_ppm: float) -> bool:
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        advapi32 = ctypes.windll.advapi32

        # 启用 SeSystemtimePrivilege（Windows 默认禁用，需显式启用）
        token = wintypes.HANDLE()
        if advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            0x0028,  # TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
            ctypes.byref(token)
        ):
            luid = wintypes.LUID()
            if advapi32.LookupPrivilegeValueW(
                None, "SeSystemtimePrivilege", ctypes.byref(luid)
            ):
                class LUID_AND_ATTRIBUTES(ctypes.Structure):
                    _fields_ = [("Luid", wintypes.LUID),
                                ("Attributes", wintypes.DWORD)]
                class TOKEN_PRIVILEGES(ctypes.Structure):
                    _fields_ = [("PrivilegeCount", wintypes.DWORD),
                                ("Privileges", LUID_AND_ATTRIBUTES * 1)]
                tp = TOKEN_PRIVILEGES()
                tp.PrivilegeCount = 1
                tp.Privileges[0].Luid = luid
                tp.Privileges[0].Attributes = 0x00000002  # SE_PRIVILEGE_ENABLED
                advapi32.AdjustTokenPrivileges(token, False,
                                                ctypes.byref(tp), 0, None, None)
            kernel32.CloseHandle(token)

        DEFAULT_ADJUSTMENT = 10000
        MIN_ADJUSTMENT = 100
        MAX_ADJUSTMENT = 100000

        adj = int(DEFAULT_ADJUSTMENT * (1 + drift_ppm / 1_000_000))
        adj = max(MIN_ADJUSTMENT, min(MAX_ADJUSTMENT, adj))

        result = kernel32.SetSystemTimeAdjustment(True, wintypes.DWORD(adj))
        if not result:
            err = ctypes.GetLastError()
            if err == 1314:
                logger.warning("Windows 频率补偿失败: 缺少系统权限 (1314)")
            else:
                logger.warning("Windows 频率补偿失败 (错误码: %d)", err)
            return False
        logger.info("Windows 频率补偿已应用: 调整值=%d (漂移=%.2f PPM)", adj, drift_ppm)
        return True
    except ImportError:
        logger.debug("ctypes.windll 不可用，非 Windows 系统")
        return False
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


def _query_ntp_server(server: str, timeout: float = NTP_TIMEOUT) -> Optional[Tuple[float, float]]:
    """
    向单个 NTP 服务器发送查询，返回 (UNIX 时间戳, 延迟秒数)。

    自动识别 IPv4/IPv6 地址并创建对应类型的 socket。
    延迟 = 接收时间戳 - 发送时间戳（time.monotonic），用于最小延迟筛选。

    Args:
        server: NTP 服务器 IP 地址（支持 IPv4 和 IPv6）
        timeout: 超时秒数

    Returns:
        (unix_timestamp, delay_seconds) 成功
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
        sock.close()
        sock = None

        delay = t_recv - t_send

        if len(data) < 48:
            logger.debug("NTP 服务器 %s 返回数据过短: %d 字节", server, len(data))
            return None

        ntp_sec = struct.unpack("!I", data[40:44])[0]
        ntp_frac = struct.unpack("!I", data[44:48])[0]
        unix_time = _ntp_timestamp_to_unix(ntp_sec, ntp_frac)
        return unix_time, delay

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


def _get_ntp_time() -> Optional[float]:
    """（旧接口）依次查询所有服务器，返回首个成功的 UNIX 时间戳。"""
    for server in NTP_SERVERS:
        result = _query_ntp_server(server)
        if result is not None:
            unix_time, _ = result
            logger.debug("成功从 NTP 服务器 %s 获取标准时间", server)
            return unix_time
    return None


def _get_ntp_time_min_delay() -> Optional[float]:
    """
    最小延迟采样（chrony 风格）：快速采样 NTP_MIN_DELAY_SAMPLES 次，
    只取延迟最小的那次结果。

    理论依据：最小延迟对应最接近真实时钟偏差（往返最为对称）。

    Returns:
        延迟最小的 NTP UNIX 时间戳，全部失败返回 None
    """
    best_time = None
    best_delay = float("inf")

    for server in NTP_SERVERS:
        for _ in range(NTP_MIN_DELAY_SAMPLES):
            result = _query_ntp_server(server)
            if result is not None:
                unix_time, delay = result
                if delay < best_delay:
                    best_delay = delay
                    best_time = unix_time
            time.sleep(NTP_MIN_DELAY_INTERVAL)
        if best_time is not None:
            logger.debug("最小延迟筛选: 服务器=%s, 延迟=%.1fms, 采样=%d次",
                         server, best_delay * 1000, NTP_MIN_DELAY_SAMPLES)
            return best_time

    return None


def _set_system_time_windows(unix_timestamp: float) -> bool:
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

        kernel32 = ctypes.windll.kernel32
        result = kernel32.SetSystemTime(ctypes.byref(st))
        if result:
            logger.info("系统时间已校准至 NTP 标准时间")
            return True
        else:
            logger.warning("设置系统时间失败 (错误码: %d)", ctypes.GetLastError())
            return False

    except ImportError:
        logger.debug("ctypes.windll 不可用，非 Windows 系统")
        return False
    except Exception as e:
        logger.warning("设置系统时间异常: %s", e)
        return False


def _set_system_time_linux(unix_timestamp: float) -> bool:
    try:
        import subprocess
        from datetime import datetime, timezone

        dt = datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
        date_str = dt.strftime("%Y-%m-%d %H:%M:%S")

        result = subprocess.run(
            ["date", "-s", date_str, "--utc"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            logger.info("系统时间已校准至 NTP 标准时间")
            return True

        result = subprocess.run(
            ["timedatectl", "set-time", date_str],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            logger.info("系统时间已通过 timedatectl 校准至 NTP 标准时间")
            return True

        logger.warning("设置系统时间失败: 无 root 权限或命令不可用")
        return False

    except FileNotFoundError:
        logger.debug("date/timedatectl 命令不可用")
        return False
    except Exception as e:
        logger.debug("设置系统时间异常: %s", e)
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
        ntp_time = _get_ntp_time_min_delay()
    else:
        ntp_time = _get_ntp_time()

    if ntp_time is None:
        logger.error(
            "NTP 校时失败：无法连接国家授时中心服务器 %s（端口 %d），"
            "所有服务器均无响应。系统时间可能不准确，证书验证将使用当前系统时间。",
            ", ".join(NTP_SERVERS), NTP_PORT
        )
        return False, 0.0

    local_time = time.time()
    offset = ntp_time - local_time

    ntp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ntp_time))
    local_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    if abs(offset) <= DEVIATION_THRESHOLD:
        logger.info(
            "NTP 校时通过：NTP=%s，本地=%s，偏差=%.2f 秒（阈值 %d 秒）",
            ntp_str, local_str, offset, DEVIATION_THRESHOLD
        )
        return True, offset

    logger.warning(
        "系统时间偏差 %.2f 秒（超过阈值 %d 秒）：NTP=%s，本地=%s。尝试校准系统时间...",
        offset, DEVIATION_THRESHOLD, ntp_str, local_str
    )

    if sys.platform == "win32":
        calibrated = _set_system_time_windows(ntp_time)
    elif sys.platform.startswith("linux"):
        calibrated = _set_system_time_linux(ntp_time)
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
                                  loop=None) -> Optional[Tuple[float, float]]:
    """异步查询单个 NTP 服务器，通过线程池避免阻塞事件循环"""
    if loop is None:
        loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _query_ntp_server, server, timeout)


async def _query_server_best(server: str, min_delay: bool) -> Optional[Tuple[float, float]]:
    """查询单台服务器多次（如果启用 min_delay），返回 (best_time, best_delay)"""
    samples = NTP_MIN_DELAY_SAMPLES if min_delay else 1
    best_time = None
    best_delay = float("inf")
    for _ in range(samples):
        result = await query_ntp_server_async(server)
        if result is not None:
            unix_time, delay = result
            if delay < best_delay:
                best_delay = delay
                best_time = unix_time
        await asyncio.sleep(NTP_MIN_DELAY_INTERVAL if min_delay else 0)
    if best_time is not None:
        return best_time, best_delay
    return None


async def get_ntp_time_async(min_delay: bool = True) -> Optional[float]:
    """
    异步并行查询所有 NTP 服务器，取最快返回的结果。
    支持最小延迟筛选：每台快速采样 NTP_MIN_DELAY_SAMPLES 次。
    使用 asyncio.wait(FIRST_COMPLETED) 及时返回，不等待慢速服务器超时。
    """
    tasks = [asyncio.create_task(_query_server_best(server, min_delay)) for server in NTP_SERVERS]
    if not tasks:
        return None

    # 总超时兜底：30 秒后不再等待
    TOTAL_TIMEOUT = 30.0
    best_time = None
    best_delay = float("inf")
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
            if result is not None and isinstance(result, tuple) and len(result) == 2:
                unix_time, delay = result
                if delay < best_delay:
                    best_delay = delay
                    best_time = unix_time

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
    return best_time


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

    ntp_time = await get_ntp_time_async(min_delay=min_delay)

    if ntp_time is None:
        logger_n.error(
            "NTP 校时失败：无法连接授时中心服务器 %s（端口 %d）",
            ", ".join(NTP_SERVERS), NTP_PORT
        )
        return False, 0.0

    local_time = time.time()
    offset = ntp_time - local_time

    ntp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ntp_time))
    local_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    if abs(offset) <= DEVIATION_THRESHOLD:
        logger_n.info(
            "NTP 校时通过：NTP=%s，本地=%s，偏差=%.2f 秒（阈值 %d 秒）",
            ntp_str, local_str, offset, DEVIATION_THRESHOLD
        )
        return True, offset

    logger_n.warning(
        "系统时间偏差 %.2f 秒（超过阈值 %d 秒）：NTP=%s，本地=%s。尝试校准系统时间...",
        offset, DEVIATION_THRESHOLD, ntp_str, local_str
    )

    if sys.platform == "win32":
        calibrated = _set_system_time_windows(ntp_time)
    elif sys.platform.startswith("linux"):
        calibrated = _set_system_time_linux(ntp_time)
    else:
        calibrated = False

    return True, offset

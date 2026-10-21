"""Windows 校时能力实测脚本（需以管理员身份运行）

用法:
    python win_time_admin_check.py             # 只检查，不改系统时间
    python win_time_admin_check.py --apply     # 真实校时（SetSystemTime 失败会自动回退 w32tm /resync /force）
    python win_time_admin_check.py --freq 20    # 额外把系统时钟频率补偿写入 20 PPM（会真的改变时钟速率）

检查内容:
  [1] 当前进程是否提升、令牌里是否真有 SeSystemtimePrivilege
  [2] GetSystemTimeAdjustment 的真实 increment（旧代码把它硬编码成 10000，是错的）
  [3] 项目里修好的 ntp_sync._enable_systemtime_privilege() 能否真正启用特权
  [4] 与授时中心的 NTP 偏差
  [5] --apply 时执行真实校时并回读验证
  [6] --freq 时写入频率补偿并回读验证
"""
import argparse
import ctypes
import logging
import os
import sys
import time
from ctypes import wintypes

PROJECT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dnscrypt-proxy")
sys.path.insert(0, PROJECT_DIR)

import ntp_sync  # noqa: E402

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


def token_report():
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                             wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.LookupPrivilegeNameW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p,
                                              wintypes.LPWSTR,
                                              ctypes.POINTER(wintypes.DWORD)]
    advapi32.LookupPrivilegeNameW.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008,
                                     ctypes.byref(token)):
        print("[1] OpenProcessToken 失败 err=%d" % ctypes.get_last_error())
        return
    need = wintypes.DWORD(0)
    advapi32.GetTokenInformation(token, 20, None, 0, ctypes.byref(need))  # TokenElevation
    buf = ctypes.create_string_buffer(need.value or 4)
    advapi32.GetTokenInformation(token, 20, buf, need.value, ctypes.byref(need))
    elevated = bool(ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value)

    need2 = wintypes.DWORD(0)
    advapi32.GetTokenInformation(token, 3, None, 0, ctypes.byref(need2))  # TokenPrivileges
    buf2 = ctypes.create_string_buffer(need2.value or 4)
    ok2 = advapi32.GetTokenInformation(token, 3, buf2, need2.value, ctypes.byref(need2))
    priv_state = None
    if ok2:
        count = ctypes.cast(buf2, ctypes.POINTER(wintypes.DWORD)).contents.value
        arr = ctypes.cast(ctypes.byref(buf2, ctypes.sizeof(wintypes.DWORD)),
                          ctypes.POINTER(LUID_AND_ATTRIBUTES * count)).contents
        for i in range(count):
            name = ctypes.create_unicode_buffer(256)
            size = wintypes.DWORD(256)
            advapi32.LookupPrivilegeNameW(None, ctypes.byref(arr[i].Luid), name,
                                          ctypes.byref(size))
            if name.value == "SeSystemtimePrivilege":
                priv_state = arr[i].Attributes
    kernel32.CloseHandle(token)

    print("[1] 进程是否提升: %s" % ("是（管理员令牌）" if elevated else "否（标准用户令牌）"))
    print("[1] 令牌中的 SeSystemtimePrivilege: %s"
          % ("不存在（非提升进程无法改系统时间）" if priv_state is None
             else "存在, attrs=0x%x（0x0=未启用, 0x2=已启用）" % priv_state))


def show_adjustment(tag="[2]"):
    kernel32.GetSystemTimeAdjustment.argtypes = [ctypes.POINTER(wintypes.DWORD),
                                                 ctypes.POINTER(wintypes.DWORD),
                                                 ctypes.POINTER(wintypes.BOOL)]
    kernel32.GetSystemTimeAdjustment.restype = wintypes.BOOL
    adj = wintypes.DWORD(0)
    inc = wintypes.DWORD(0)
    dis = wintypes.BOOL(True)
    ok = kernel32.GetSystemTimeAdjustment(ctypes.byref(adj), ctypes.byref(inc),
                                          ctypes.byref(dis))
    print("%s GetSystemTimeAdjustment ok=%s adjustment=%d increment=%d disabled=%s"
          % (tag, ok, adj.value, inc.value, bool(dis.value)))
    return inc.value or 156250


def restore_frequency():
    """交回 Windows 自身的时间同步：SetSystemTimeAdjustment(0, TRUE)。

    写入频率补偿后系统会处于「本进程接管时钟速率、Windows 不再自行纠正」状态；
    测完可以用 --restore-freq 把控制权交回系统。
    """
    ntp_sync._enable_systemtime_privilege()
    kernel32.SetSystemTimeAdjustment.argtypes = [wintypes.DWORD, wintypes.BOOL]
    kernel32.SetSystemTimeAdjustment.restype = wintypes.BOOL
    ok = kernel32.SetSystemTimeAdjustment(0, True)
    print("[7] 交回系统自行同步 -> %s (err=%d)" % (bool(ok), ctypes.get_last_error()))
    show_adjustment("[7]")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="真实校时（改系统时间）")
    parser.add_argument("--freq", type=float, default=None,
                        help="写入频率补偿（单位 PPM，会改变时钟速率）")
    parser.add_argument("--restore-freq", action="store_true",
                        help="交回 Windows 自身同步：SetSystemTimeAdjustment(0, TRUE)")
    args = parser.parse_args()

    if args.restore_freq:
        token_report()
        restore_frequency()
        return

    token_report()
    print("[3] 启用 SeSystemtimePrivilege:", ntp_sync._enable_systemtime_privilege())
    show_adjustment("[3]")

    sample = ntp_sync._get_ntp_time_min_delay()
    if sample is None:
        print("[4] 无法从授时中心取到时间，跳过偏差测量")
        return
    ntp_time, local_at_sample = sample
    elapsed = time.time() - local_at_sample
    offset = ntp_time - local_at_sample        # 真实偏差（不含采样耗时）
    print("[4] NTP 偏差 = %+.3f 秒（NTP=%s，本地采样时刻=%s，采样耗时 %.1f 秒）"
          % (offset, time.strftime("%F %T", time.localtime(ntp_time)),
             time.strftime("%F %T", time.localtime(local_at_sample)), elapsed))

    if args.apply:
        # 采样到设置之间有流逝，必须外推到「现在」再写，否则会设成旧值
        target = ntp_time + (time.time() - local_at_sample)
        ok = ntp_sync._set_system_time_windows(target)
        print("[5] 校时结果: %s；校时后偏差 = %+.3f 秒"
              % (ok, target - time.time()))
    else:
        print("[5] 未加 --apply，不改系统时间（要真实校时请加 --apply）")

    if args.freq is not None:
        ok = ntp_sync._apply_drift_windows(args.freq)
        print("[6] 写入频率补偿 %.2f PPM -> %s" % (args.freq, ok))
        show_adjustment("[6]")


if __name__ == "__main__":
    main()

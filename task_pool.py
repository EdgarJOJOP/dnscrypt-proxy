"""阻塞任务的线程池分级与优先级调度

背景
----
迭代 DNS 查询（``dns.query.udp``）、NTP 校时（socket + 设置系统时间）、
NDP/ARP 的 scapy 抓包发包、日志文件裁剪都是**阻塞调用**，必须借线程执行。
CPython 的 asyncio 只有一个默认 executor（``min(32, cpu+4)`` 个线程），
一旦迭代查询把它占满，其它任务只能在队列里排队（实测可延迟近 1 秒）。

因此这里把阻塞任务分三类通道：

    阻塞任务 ──┬── NTP 专属池（2 线程）：校时必须及时，不参与排队
               ├── 日志裁剪专属池（1 线程）：它在 DNS 查询的 await 链上
               │   （log → flush → trim），若与 DNS 共享队列会形成
               │   「DNS 等日志、日志等线程」的死锁，故必须独立
               └── 共享池（``PriorityGate`` 排序）
                   DNS 迭代查询（等级 1）> NDP 防护（等级 2）> ARP 防护（等级 3）
                   等待超过 ``AGING_SECONDS`` 自动提级，防止低优先级饿死

说明：优先级只能决定「谁先拿到空闲线程」，**不能抢占**正在执行的任务。
所以需要「绝对及时」的 NTP 走独立池，而不是和迭代查询抢优先级。

用法::

    from task_pool import TaskLevel, run_blocking, run_ntp, run_log_io

    resp = await run_blocking(TaskLevel.DNS, self._query_one, ip, qname, qtype)
    await run_ntp(_query_ntp_server, server, timeout)
    await run_log_io(self._trim_file_sync, filepath)
"""

import asyncio
import itertools
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple

logger = logging.getLogger("dns-proxy.task-pool")


class TaskLevel:
    """阻塞任务优先级（数值越小越优先）"""

    NTP = 0     # NTP 校时（实际走专属池，此值仅用于语义对齐）
    DNS = 1     # 迭代 DNS 查询：直接影响用户解析延迟
    NDP = 2     # NDP 防护的 scapy 抓包/发包
    ARP = 3     # ARP 防护的 scapy 发包


# 低优先级等待超过该秒数后自动提级（每 AGING_SECONDS 提一级，最多提到 0）
AGING_SECONDS = 3.0


class _Acquire:
    """``PriorityGate.acquire()`` 返回的异步上下文管理器"""

    __slots__ = ("_gate", "_level", "_acquired")

    def __init__(self, gate: "PriorityGate", level: int):
        self._gate = gate
        self._level = int(level)
        self._acquired = False

    async def __aenter__(self):
        await self._gate._acquire(self._level)
        self._acquired = True
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._acquired:
            self._acquired = False
            self._gate.release()
        return False


class PriorityGate:
    """按优先级准入的异步闸门（名额数 = 共享线程池的线程数）

    仅在「名额已满」时才排队；排队期间高等级任务先被唤醒，
    低等级任务等待超过 ``aging`` 秒会自动提级（防止被持续的高优先级任务饿死）。
    """

    def __init__(self, limit: int, aging: float = AGING_SECONDS):
        self._limit = max(1, int(limit))
        self._aging = max(0.5, float(aging))
        self._active = 0
        # (level, seq, fut, enqueue_time)
        self._waiters: List[Tuple[int, int, asyncio.Future, float]] = []
        self._seq = itertools.count()

    # ---------- 对外接口 ----------

    def acquire(self, level: int) -> _Acquire:
        return _Acquire(self, level)

    def release(self):
        if self._active > 0:
            self._active -= 1
        self._dispatch()

    @property
    def active(self) -> int:
        return self._active

    @property
    def waiting(self) -> int:
        return len(self._waiters)

    # ---------- 内部实现 ----------

    async def _acquire(self, level: int):
        # 空闲且无人排队：直接进
        if self._active < self._limit and not self._waiters:
            self._active += 1
            return
        fut = asyncio.get_running_loop().create_future()
        self._waiters.append((int(level), next(self._seq), fut, time.monotonic()))
        # 名额可能在入队瞬间被释放，补一次调度避免错过唤醒
        self._dispatch()
        try:
            await fut
        except asyncio.CancelledError:
            self._waiters = [w for w in self._waiters if w[2] is not fut]
            raise

    def _dispatch(self):
        while self._active < self._limit and self._waiters:
            # 丢弃已取消/已完成的等待者
            self._waiters = [w for w in self._waiters if not w[2].done()]
            if not self._waiters:
                return
            now = time.monotonic()
            best_idx = 0
            best_key = None
            for idx, (level, seq, fut, enq) in enumerate(self._waiters):
                # 老化：等待越久等级越高（最多提到 0）
                boost = int((now - enq) // self._aging)
                effective = level - boost
                if effective < 0:
                    effective = 0
                key = (effective, seq)
                if best_key is None or key < best_key:
                    best_key = key
                    best_idx = idx
            level, seq, fut, enq = self._waiters.pop(best_idx)
            if fut.done():
                continue
            self._active += 1
            if not fut.done():
                fut.set_result(True)


# ==================== 全局单例（惰性创建） ====================

_SHARED_POOL: Optional[ThreadPoolExecutor] = None
_SHARED_GATE: Optional[PriorityGate] = None
_NTP_POOL: Optional[ThreadPoolExecutor] = None
_LOG_POOL: Optional[ThreadPoolExecutor] = None


def _shared_workers() -> int:
    """共享池默认线程数：可用核数 × 2

    口径与 ``performance.cpu_core_limit`` 一致（0 = 总核数 - 1），
    因此默认 =(cpu-1)×2；main 启动时会用
    ``config.effective_cpu_cores × 2`` 覆盖（用户调小核数即调小线程数）。
    """
    cores = max(1, (os.cpu_count() or 4) - 1)
    return max(2, min(64, cores * 2))


def get_shared_pool() -> Tuple[ThreadPoolExecutor, PriorityGate]:
    """共享池 + 对应闸门（DNS/NDP/ARP 共用，按优先级排队）"""
    global _SHARED_POOL, _SHARED_GATE
    if _SHARED_POOL is None:
        workers = _shared_workers()
        _SHARED_POOL = ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="dns-shared",
        )
        _SHARED_GATE = PriorityGate(workers)
    return _SHARED_POOL, _SHARED_GATE


def get_ntp_pool() -> ThreadPoolExecutor:
    """NTP 专属池：校时必须及时，不与任何任务排队"""
    global _NTP_POOL
    if _NTP_POOL is None:
        _NTP_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="dns-ntp")
    return _NTP_POOL


def get_log_pool() -> ThreadPoolExecutor:
    """日志裁剪专属池：它在 DNS 查询的 await 链上，必须独立避免死锁"""
    global _LOG_POOL
    if _LOG_POOL is None:
        _LOG_POOL = ThreadPoolExecutor(max_workers=1, thread_name_prefix="dns-log")
    return _LOG_POOL


# ==================== 便捷调用 ====================


async def run_blocking(level: int, fn, *args):
    """在共享池里按优先级执行阻塞调用（DNS/NDP/ARP 用这个）"""
    loop = asyncio.get_running_loop()
    pool, gate = get_shared_pool()
    async with gate.acquire(level):
        return await loop.run_in_executor(pool, fn, *args)


def get_pressure() -> float:
    """共享池当前压力（0.0=空闲，1.0=满负荷/排队）

    调用方（如迭代查询）可据此降低并行度：压力大时每批只发 1 台，
    减少线程争用与上下文切换——用户机器上还有游戏/其它软件要跑。
    """
    if _SHARED_GATE is None:
        return 0.0
    limit = max(1, _SHARED_GATE._limit)
    busy = _SHARED_GATE._active + _SHARED_GATE.waiting
    return min(1.0, busy / limit)


def configure_shared_pool(workers: int = 0):
    """在创建共享池之前设置线程数（0 或非法值 = 用默认保守值）

    必须在首次 ``get_shared_pool()`` 之前调用；池已创建时忽略并记一条 debug。
    """
    global _SHARED_POOL, _SHARED_GATE
    try:
        wanted = int(workers or 0)
    except (TypeError, ValueError):
        wanted = 0
    if wanted <= 0:
        return
    if _SHARED_POOL is not None:
        logger.debug("共享池已创建，忽略 workers=%s", wanted)
        return
    workers = max(2, min(64, wanted))
    _SHARED_POOL = ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="dns-shared",
    )
    _SHARED_GATE = PriorityGate(workers)
    logger.info(
        "阻塞任务共享池: %d 线程（由 performance.cpu_core_limit 推导：核数×2）",
        workers,
    )


async def run_ntp(fn, *args):
    """在 NTP 专属池执行阻塞调用（不排队）"""
    return await asyncio.get_running_loop().run_in_executor(get_ntp_pool(), fn, *args)


async def run_log_io(fn, *args):
    """在日志专属池执行阻塞 IO（不排队、不与 DNS 争线程）"""
    return await asyncio.get_running_loop().run_in_executor(get_log_pool(), fn, *args)

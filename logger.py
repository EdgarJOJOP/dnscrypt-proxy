"""
日志模块
- TrimFileHandler: 通用的日志文件自动裁剪处理器（所有系统日志通用）
- RequestLogger: 异步 DNS 请求日志记录器（内存缓冲 + JSON + 裁剪）
"""

import os
import json
import time
import asyncio
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from collections import deque

system_logger = logging.getLogger("dns-proxy.logger")


class TrimFileHandler(logging.FileHandler):
    """
    带自动裁剪功能的日志文件处理器。
    可设置最大文件大小（MB），超出后自动裁剪，保留后半部分。
    用法透明：替换 logging.FileHandler 即可。
    """

    # 裁剪后保留的比例（如 0.6 = 保留文件后半部分的 60%）
    TRIM_KEEP_RATIO = 0.6
    # 最小检查间隔（秒），避免频繁 stat
    MIN_CHECK_INTERVAL = 30

    def __init__(self, filename: str, max_log_size_mb: int = 100,
                 mode: str = "a", encoding: str = "utf-8", delay: bool = False):
        super().__init__(filename, mode, encoding, delay)
        self._max_bytes = max_log_size_mb * 1024 * 1024
        self._last_check = 0.0

    def emit(self, record):
        """写入日志记录后检查文件大小"""
        super().emit(record)
        self._maybe_trim()

    def _maybe_trim(self):
        """检查文件大小，超限则裁剪"""
        now = time.monotonic()
        if now - self._last_check < self.MIN_CHECK_INTERVAL:
            return
        self._last_check = now
        try:
            size = os.path.getsize(self.baseFilename)
            if size < self._max_bytes:
                return
        except OSError:
            return
        self._trim_file()

    def _trim_file(self):
        """关闭文件 → 读取全部行 → 保留后半部分 → 重写 → 重新打开"""
        try:
            self.flush()
            self.close()
        except Exception as e:
            system_logger.debug("日志裁剪关闭文件异常: %s", e)
        try:
            fp = Path(self.baseFilename)
            lines = fp.read_text(encoding="utf-8").splitlines(True)
            if not lines:
                return
            total = len(lines)
            keep_start = int(total * (1 - self.TRIM_KEEP_RATIO))
            kept = lines[keep_start:]
            removed = total - len(kept)
            fp.write_text("".join(kept), encoding="utf-8")
            system_logger.info(
                "日志裁剪 [%s]: 移除 %d 行，保留 %d 行 (当前 %.1fMB)",
                fp.name, removed, len(kept), fp.stat().st_size / (1024 * 1024),
            )
        except Exception as e:
            system_logger.error("日志裁剪失败 [%s]: %s", self.baseFilename, e)
        finally:
            # 重新打开文件流
            try:
                self.stream = self._open()
            except Exception as e:
                system_logger.debug("日志裁剪重新打开文件异常: %s", e)


class RequestLogger:
    """异步 DNS 请求日志记录器"""

    # 裁剪后保留的比例（如 0.6 = 保留文件后半部分的 60%）
    TRIM_KEEP_RATIO = 0.6
    # 最小检查间隔（秒），避免频繁 stat
    MIN_CHECK_INTERVAL = 30

    def __init__(
        self,
        log_dir: str = "logs",
        log_file: str = "dns_queries.log",
        buffer_size: int = 500,
        flush_interval: int = 10,
        enabled: bool = True,
        detailed: bool = True,
        max_log_size_mb: int = 100,
    ):
        self.log_dir = Path(log_dir)
        self.log_file = log_file
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval
        self.enabled = enabled
        self.detailed = detailed
        self.max_log_size_bytes = max_log_size_mb * 1024 * 1024

        # 内存缓冲区（使用 deque 限制最大长度）
        self._buffer: deque = deque(maxlen=buffer_size * 2)
        self._flush_lock = asyncio.Lock()
        self._total_logged = 0
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._last_size_check = 0.0  # 上次检查文件大小的时间戳

        # 确保日志目录存在
        self.log_dir.mkdir(parents=True, exist_ok=True)

    async def start(self):
        """启动定时刷新任务"""
        if not self.enabled:
            return
        self._running = True
        self._task = asyncio.create_task(self._periodic_flush())
        system_logger.info(
            "日志系统已启动 (buffer=%d, flush_interval=%ds, max_log_size=%dMB)",
            self.buffer_size,
            self.flush_interval,
            self.max_log_size_bytes // (1024 * 1024),
        )

    async def stop(self):
        """停止并强制刷新"""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self.flush()

    async def log(
        self,
        client_ip: str,
        domain: str,
        qtype: str,
        response_time: float,
        status: str,
        upstream: str = "",
        block_reason: str = "",
    ):
        """记录一条 DNS 请求日志（放入内存缓冲区）"""
        if not self.enabled:
            return

        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "client_ip": client_ip,
            "domain": domain,
            "qtype": qtype,
        }

        if self.detailed:
            entry.update(
                {
                    "response_time_ms": round(response_time * 1000, 2),
                    "status": status,
                    "upstream": upstream,
                    "block_reason": block_reason,
                }
            )

        self._buffer.append(entry)

        # 达到缓冲阈值，触发写入文件并清空
        if len(self._buffer) >= self.buffer_size:
            await self.flush()

    async def flush(self):
        """将缓冲区日志写入文件并清空缓冲区"""
        if not self._buffer:
            return

        async with self._flush_lock:
            if not self._buffer:
                return

            # 取出所有缓冲数据
            entries = list(self._buffer)
            self._buffer.clear()

        try:
            filepath = self.log_dir / self.log_file
            with open(filepath, "a", encoding="utf-8") as f:
                for entry in entries:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")

            self._total_logged += len(entries)

            # 写入后检查文件大小（非每次检查，有最小间隔）
            now = time.monotonic()
            if now - self._last_size_check >= self.MIN_CHECK_INTERVAL:
                self._last_size_check = now
                await self._maybe_trim_file(filepath)

        except Exception as e:
            system_logger.error("写入日志文件失败: %s", e)

    async def _maybe_trim_file(self, filepath: Path):
        """
        检查日志文件大小，超过限制则异步裁剪（保留后半部分）。
        """
        try:
            size = filepath.stat().st_size
            if size < self.max_log_size_bytes:
                return

            # 在 executor 中执行文件 IO，不阻塞事件循环
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._trim_file_sync, filepath)
        except FileNotFoundError:
            pass
        except Exception as e:
            system_logger.error("检查日志文件大小失败: %s", e)

    def _trim_file_sync(self, filepath: Path):
        """
        同步裁剪日志文件（在 executor 中运行）。
        读取所有行，保留后半部分（TRIM_KEEP_RATIO），重写文件。
        """
        system_logger.info(
            "日志文件 %.1fMB 超过限制 %dMB，开始裁剪...",
            filepath.stat().st_size / (1024 * 1024),
            self.max_log_size_bytes // (1024 * 1024),
        )

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()

            if not lines:
                return

            total = len(lines)
            keep_start = int(total * (1 - self.TRIM_KEEP_RATIO))
            kept = lines[keep_start:]
            removed = total - len(kept)

            with open(filepath, "w", encoding="utf-8") as f:
                f.writelines(kept)

            # 更新总计数（近似值）
            self._total_logged = max(0, self._total_logged - removed)

            system_logger.info(
                "日志裁剪完成: 移除 %d 条旧记录，保留 %d 条 (当前大小 %.1fMB)",
                removed, len(kept), filepath.stat().st_size / (1024 * 1024),
            )
        except Exception as e:
            system_logger.error("裁剪日志文件失败: %s", e)

    async def _periodic_flush(self):
        """定时刷新任务"""
        while self._running:
            try:
                await asyncio.sleep(self.flush_interval)
                if self._buffer:
                    await self.flush()
            except asyncio.CancelledError:
                break
            except Exception as e:
                system_logger.error("定时刷新日志异常: %s", e)

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "buffer_size": len(self._buffer),
            "buffer_max": self.buffer_size,
            "total_logged": self._total_logged,
            "enabled": self.enabled,
            "max_log_size_mb": self.max_log_size_bytes // (1024 * 1024),
        }

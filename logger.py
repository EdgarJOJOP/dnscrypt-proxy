"""
异步请求日志模块
- 内存缓冲，达到阈值后写入文件并清空内存
- 定时刷新确保日志不丢失
- JSON 格式记录
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


class RequestLogger:
    """异步 DNS 请求日志记录器"""

    def __init__(
        self,
        log_dir: str = "logs",
        log_file: str = "dns_queries.log",
        buffer_size: int = 500,
        flush_interval: int = 10,
        enabled: bool = True,
        detailed: bool = True,
    ):
        self.log_dir = Path(log_dir)
        self.log_file = log_file
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval
        self.enabled = enabled
        self.detailed = detailed

        # 内存缓冲区（使用 deque 限制最大长度）
        self._buffer: deque = deque(maxlen=buffer_size * 2)
        self._flush_lock = asyncio.Lock()
        self._total_logged = 0
        self._running = False
        self._task: Optional[asyncio.Task] = None

        # 确保日志目录存在
        self.log_dir.mkdir(parents=True, exist_ok=True)

    async def start(self):
        """启动定时刷新任务"""
        if not self.enabled:
            return
        self._running = True
        self._task = asyncio.create_task(self._periodic_flush())
        system_logger.info(
            "日志系统已启动 (buffer=%d, flush_interval=%ds)",
            self.buffer_size,
            self.flush_interval,
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

        except Exception as e:
            system_logger.error("写入日志文件失败: %s", e)

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
        }

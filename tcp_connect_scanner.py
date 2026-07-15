#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块名称：tcp_connect_scanner.py

功能：
    实现 TCP connect 端口扫描功能，支持并发扫描、暂停、继续、取消、
    扫描速度模式预设、扫描统计和 GUI 结构化返回结果。

扫描原理：
    TCP connect 扫描是最基本的 TCP 扫描方式。
    如果目标端口处于监听状态，connect() 成功，表示端口开放。
    如果目标端口关闭，connect() 失败并抛出 socket error，表示端口关闭或连接失败。

注意：
    本模块只判断端口状态。
    service 字段中的常见服务名称主要来自端口映射。
    主机初始状态由 ICMP 模块提供。
    最终主机状态由 ICMP 与 TCP Connect 响应综合判断：
    TCP 出现 open 或明确的 closed 时，可以确认目标主机在线。

    ★ 暂停只停止继续提交新任务，已经开始运行或已提交的少量任务可能继续完成。
      Python 无法安全强制终止已经运行的工作线程。
"""

import errno
import socket
import threading
import time
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from typing import Any, Callable, Dict, List, Optional

try:
    from .models import TCPConnectScanResult
    from .utils import parse_ports
except ImportError:
    from models import TCPConnectScanResult
    from utils import parse_ports


# ============================================================================
# 常量定义
# ============================================================================

SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
    "slow": {
        "display_name": "慢速",
        "max_workers": 20,
        "description": "网络较差或教学演示",
    },
    "normal": {
        "display_name": "普通",
        "max_workers": 100,
        "description": "默认扫描",
    },
    "fast": {
        "display_name": "快速",
        "max_workers": 300,
        "description": "本地实验环境",
    },
    "custom": {
        "display_name": "自定义",
        "max_workers": None,
        "description": "高级用户自定义并发数",
    },
}

PORT_STATUS_DISPLAY: Dict[str, str] = {
    "open": "开放",
    "closed": "关闭",
    "filtered": "被过滤",
    "error": "错误",
    "cancelled": "已取消",
}

COMMON_SERVICES: Dict[int, str] = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP",
    8443: "HTTPS",
    27017: "MongoDB",
}

VALID_HOST_STATUSES = {"在线", "离线"}


# ============================================================================
# connect_ex() 错误码分类（跨平台兼容 Linux errno 与 Windows WSA 代码）
# ============================================================================

# 连接拒绝 → 端口关闭（只有这一种情况）
_CLOSED_CODES: set = {
    getattr(errno, "ECONNREFUSED", 10061),
    10061,  # Windows WSAECONNREFUSED
}

# 超时 / 主机不可达 → 被过滤
_FILTERED_CODES: set = {
    getattr(errno, "ETIMEDOUT", 10060),
    getattr(errno, "EHOSTUNREACH", 10065),
    10060,  # Windows WSAETIMEDOUT
    10065,  # Windows WSAEHOSTUNREACH
}

# 网络不可达 / 资源暂不可用 / 权限不足 → 错误
_ERROR_CODES: set = {
    getattr(errno, "ENETUNREACH", 10051),
    getattr(errno, "EAGAIN", 11),
    getattr(errno, "EWOULDBLOCK", 10035),
    getattr(errno, "EACCES", 10013),
    10013,  # Windows WSAEACCES
    10051,  # Windows WSAENETUNREACH
}


# ============================================================================
# 辅助函数
# ============================================================================

def resolve_final_host_status(
    icmp_status_code: str,
    tcp_results: List[TCPConnectScanResult],
) -> str:
    """综合 ICMP 和 TCP Connect 扫描结果判断主机最终状态。

    规则：
        1. TCP 存在 open 或 closed → 主机一定在线（即便 ICMP 失败）。
        2. ICMP 成功 → 在线。
        3. 其余情况 → 离线。

    Args:
        icmp_status_code: ICMP 探测原始状态码，"online" 或 "offline"
        tcp_results: TCP Connect 扫描结果列表

    Returns:
        "online" 或 "offline"
    """
    # 规则 1：TCP 有 open 或 closed，主机一定在线
    if any(result.status in {"open", "closed"} for result in tcp_results):
        return "online"

    # 规则 2：ICMP 成功，主机在线
    if icmp_status_code == "online":
        return "online"

    # 规则 3：其余情况视为离线
    return "offline"


def resolve_max_workers(
    profile_key: str = "normal",
    custom_workers: Optional[int] = None,
) -> int:
    """根据扫描速度模式解析实际并发数。

    Args:
        profile_key: 扫描模式键名，可选 slow / normal / fast / custom
        custom_workers: 自定义模式下的并发数

    Returns:
        实际并发数

    Raises:
        ValueError: 模式未知或参数不合法
    """
    if profile_key not in SCAN_PROFILES:
        raise ValueError(
            f"未知扫描模式：{profile_key}，可选值："
            + ", ".join(SCAN_PROFILES.keys())
        )

    if profile_key == "custom":
        if custom_workers is None:
            raise ValueError("自定义模式（custom）必须提供 custom_workers 参数")
        if not isinstance(custom_workers, int):
            raise ValueError("custom_workers 必须是整数")
        if custom_workers < 1 or custom_workers > 500:
            raise ValueError("custom_workers 必须在 1～500 之间")
        return custom_workers

    return int(SCAN_PROFILES[profile_key]["max_workers"])


def result_to_ui_dict(
    result: TCPConnectScanResult,
    host_status: str,
) -> Dict[str, Any]:
    """将单个 TCPConnectScanResult 转换为 GUI 需要的字典格式。

    service 字段根据常见端口映射推测，并非协议确认或 Banner 探测结果。

    Args:
        result: TCP Connect 扫描结果对象
        host_status: 最终主机状态（"在线" 或 "离线"）

    Returns:
        严格包含 6 个字段的字典

    Raises:
        ValueError: host_status 不合法
    """
    if host_status not in VALID_HOST_STATUSES:
        raise ValueError(
            f"host_status 只能是：{'、'.join(sorted(VALID_HOST_STATUSES))}"
        )

    service = COMMON_SERVICES.get(result.port, "未知")

    return {
        "ip": result.host,
        "host_status": host_status,
        "method": "TCP Connect",
        "port": result.port,
        "port_status": PORT_STATUS_DISPLAY.get(result.status, "未知"),
        "service": service,
    }


def results_to_ui_dicts(
    results: List[TCPConnectScanResult],
    host_status: str,
) -> List[Dict[str, Any]]:
    """将 TCPConnectScanResult 列表转换为 GUI 需要的字典列表。

    所有条目的 host_status 保持一致，由调用方在综合判断后传入。

    Args:
        results: TCP Connect 扫描结果列表
        host_status: 最终主机状态（"在线" 或 "离线"）

    Returns:
        字典列表，每项严格包含 6 个字段

    Raises:
        ValueError: host_status 不合法
    """
    if host_status not in VALID_HOST_STATUSES:
        raise ValueError(
            f"host_status 只能是：{'、'.join(sorted(VALID_HOST_STATUSES))}"
        )

    return [result_to_ui_dict(r, host_status) for r in results]


# ============================================================================
# _invoke_progress_callback —— 兼容新旧进度回调
# ============================================================================

def _invoke_progress_callback(
    callback: Optional[Callable],
    completed: int,
    total: int,
    result: Optional[TCPConnectScanResult] = None,
) -> None:
    """安全调用进度回调，兼容新旧两种签名。

    新签名：(completed, total, result: TCPConnectScanResult)
    旧签名：(completed, total)

    如果回调需要 3 个参数但发生 TypeError，自动回退到两参数调用。
    回调内部异常不向外传播。
    """
    if callback is None:
        return
    try:
        callback(completed, total, result)
    except TypeError:
        # 可能是不接受第三个参数的旧接口
        try:
            callback(completed, total)
        except Exception:
            pass
    except Exception:
        pass


# ============================================================================
# ScanStatistics —— 扫描统计
# ============================================================================

class ScanStatistics:
    """扫描统计数据容器。

    所有统计基于最终去重结果计算，保证与结果列表完全一致。
    """

    def __init__(self) -> None:
        self.total_ports: int = 0
        self.open_ports: int = 0
        self.closed_ports: int = 0
        self.filtered_ports: int = 0
        self.error_ports: int = 0
        self.cancelled_ports: int = 0

    @classmethod
    def from_results(
        cls, results: List[TCPConnectScanResult]
    ) -> "ScanStatistics":
        """根据最终结果列表生成统计。"""
        stats = cls()
        stats.total_ports = len(results)

        for r in results:
            if r.status == "open":
                stats.open_ports += 1
            elif r.status == "closed":
                stats.closed_ports += 1
            elif r.status == "filtered":
                stats.filtered_ports += 1
            elif r.status == "error":
                stats.error_ports += 1
            elif r.status == "cancelled":
                stats.cancelled_ports += 1

        return stats

    def to_dict(self) -> Dict[str, int]:
        """转为字典，方便 GUI 使用。"""
        return {
            "total_ports": self.total_ports,
            "open_ports": self.open_ports,
            "closed_ports": self.closed_ports,
            "filtered_ports": self.filtered_ports,
            "error_ports": self.error_ports,
            "cancelled_ports": self.cancelled_ports,
        }

    def validate(self) -> bool:
        """校验统计与结果数量是否一致。"""
        return (
            self.total_ports
            == self.open_ports
            + self.closed_ports
            + self.filtered_ports
            + self.error_ports
            + self.cancelled_ports
        )


# ============================================================================
# ScanTaskController —— 扫描任务控制器
# ============================================================================

class ScanTaskController:
    """扫描任务控制器，统一管理扫描任务的状态、暂停、恢复和取消。

    所有状态变化仅由本控制器触发。
    禁止外部直接访问 _status、_lock 等私有字段。

    状态流转：
        waiting → running → completed
        waiting → running → paused → running → ...
        waiting → running → cancelled
        waiting → running → failed
    """

    VALID_STATUSES = {"waiting", "running", "paused", "cancelled", "completed", "failed"}

    def __init__(self) -> None:
        self._status: str = "waiting"
        self._lock: threading.Lock = threading.Lock()
        self._status_callback: Optional[Callable[[str], None]] = None
        self._last_notified_status: Optional[str] = None

        # 暂停：Condition 避免忙等待
        self._pause_condition: threading.Condition = threading.Condition()
        self._paused: bool = False

        # 取消
        self._cancel_event: threading.Event = threading.Event()

    # ---- 状态回调 ----

    def set_status_callback(
        self, callback: Optional[Callable[[str], None]]
    ) -> None:
        """设置状态变化回调函数。传 None 可清除。"""
        with self._lock:
            self._status_callback = callback

    # ---- 状态管理 ----

    def get_status(self) -> str:
        """获取当前任务状态（线程安全）。"""
        with self._lock:
            return self._status

    def _set_status(self, new_status: str) -> None:
        """设置新状态并触发回调（线程安全）。

        同一个状态不会连续重复通知。回调异常不破坏任务。
        """
        if new_status not in self.VALID_STATUSES:
            return

        with self._lock:
            if new_status == self._status:
                return
            self._status = new_status

            if new_status == self._last_notified_status:
                return
            self._last_notified_status = new_status

            callback = self._status_callback

        if callback is not None:
            try:
                callback(new_status)
            except Exception:
                pass

    # ---- 暂停 / 恢复 ----

    def pause(self) -> None:
        """暂停扫描任务。

        暂停只停止继续提交新任务，已经开始运行或已提交的少量任务可能继续完成。
        Python 无法安全强制终止已经运行的工作线程。
        """
        with self._pause_condition:
            if not self._paused:
                self._paused = True
                self._set_status("paused")

    def resume(self) -> None:
        """恢复扫描任务。"""
        with self._pause_condition:
            if self._paused:
                self._paused = False
                self._pause_condition.notify_all()
                self._set_status("running")

    def is_paused(self) -> bool:
        """检查是否处于暂停状态。"""
        with self._pause_condition:
            return self._paused

    def _wait_if_paused(self) -> None:
        """在暂停状态下阻塞等待，直到恢复或取消。使用 Condition 避免忙等待。"""
        with self._pause_condition:
            while self._paused and not self._cancel_event.is_set():
                self._pause_condition.wait(timeout=0.5)

    def start(self) -> None:
        """启动扫描任务（公开方法）。"""
        self._set_status("running")

    def wait_if_paused(self) -> None:
        """如果暂停则阻塞等待（公开方法）。"""
        self._wait_if_paused()

    # ---- 取消 ----

    def cancel(self) -> None:
        """取消扫描任务。cancel() 会唤醒处于暂停状态的线程。"""
        self._cancel_event.set()
        with self._pause_condition:
            self._pause_condition.notify_all()
        self._set_status("cancelled")

    def is_cancelled(self) -> bool:
        """检查是否已取消。"""
        return self._cancel_event.is_set()

    # ---- 完成 / 失败 ----

    def mark_completed(self) -> None:
        """标记任务完成。"""
        self._set_status("completed")

    def mark_failed(self) -> None:
        """标记任务失败。"""
        self._set_status("failed")

    # ---- 重置 ----

    def reset(self) -> None:
        """重置控制器到初始状态（线程安全）。

        注意锁顺序与 pause() 保持一致（先 _pause_condition 后 _lock），避免死锁。
        """
        # 先重置 pause 相关状态（与 pause() 的锁顺序一致）
        with self._pause_condition:
            self._paused = False
            self._pause_condition.notify_all()

        # 再重置 status 相关状态
        with self._lock:
            self._status = "waiting"
            self._last_notified_status = None

        self._cancel_event.clear()


# ============================================================================
# TCPConnectScanner —— TCP Connect 扫描器
# ============================================================================

class TCPConnectScanner:
    """TCP Connect 扫描器，支持并发扫描、暂停、继续、取消和速度模式预设。

    使用示例：
        scanner = TCPConnectScanner.from_profile(profile_key="normal", timeout=1.0)

        controller = ScanTaskController()
        controller.set_status_callback(lambda s: print(f"状态：{s}"))
        results = scanner.scan_ports("127.0.0.1", [22, 80], controller=controller)

        ui_results = scanner.scan_ports_for_ui(
            host="127.0.0.1", ports=[22, 80], host_status="在线",
        )
    """

    def __init__(
        self,
        timeout: float = 1.0,
        max_workers: int = 100,
        max_pending: Optional[int] = None,
    ) -> None:
        """初始化 TCP Connect 扫描器。

        Args:
            timeout: 单个端口连接超时时间（秒），必须 > 0
            max_workers: 最大工作线程数，范围 1～500
            max_pending: 同时进行的最大 Future 数量，默认等于 max_workers

        Raises:
            ValueError: 参数不合法
        """
        # ---- 输入校验 ----
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
            raise ValueError("timeout 必须是大于 0 的数字")
        if timeout <= 0:
            raise ValueError("timeout 必须大于 0")

        if not isinstance(max_workers, int) or isinstance(max_workers, bool):
            raise ValueError("max_workers 必须是整数")
        if max_workers < 1 or max_workers > 500:
            raise ValueError("max_workers 必须在 1～500 之间")

        if max_pending is not None:
            if not isinstance(max_pending, int) or isinstance(max_pending, bool):
                raise ValueError("max_pending 必须是正整数")
            if max_pending < 1:
                raise ValueError("max_pending 必须是正整数")

        self.timeout: float = float(timeout)
        self._max_workers: int = max_workers
        self._max_pending: int = (
            max_pending if max_pending is not None else max_workers
        )

        self._internal_controller: Optional[ScanTaskController] = None
        self._scan_lock: threading.Lock = threading.Lock()
        self._statistics: Optional[ScanStatistics] = None

    # ---- 工厂方法 ----

    @classmethod
    def from_profile(
        cls,
        profile_key: str = "normal",
        custom_workers: Optional[int] = None,
        timeout: float = 1.0,
        max_pending: Optional[int] = None,
    ) -> "TCPConnectScanner":
        """根据扫描速度模式创建扫描器。

        Args:
            profile_key: 扫描模式 slow / normal / fast / custom
            custom_workers: 自定义并发数（仅 custom 模式使用）
            timeout: 连接超时时间（秒）
            max_pending: 最大同时进行任务数

        Returns:
            TCPConnectScanner 实例

        Raises:
            ValueError: 参数不合法
        """
        workers = resolve_max_workers(profile_key, custom_workers)
        return cls(timeout=timeout, max_workers=workers, max_pending=max_pending)

    # ---- 只读属性 ----

    @property
    def max_workers(self) -> int:
        """最大工作线程数（只读）。"""
        return self._max_workers

    # ---- 公开控制接口（委托给内部控制器） ----

    def pause(self) -> None:
        """暂停当前扫描任务。"""
        ctrl = self._internal_controller
        if ctrl is not None:
            ctrl.pause()

    def resume(self) -> None:
        """恢复当前扫描任务。"""
        ctrl = self._internal_controller
        if ctrl is not None:
            ctrl.resume()

    def cancel(self) -> None:
        """取消当前扫描任务。"""
        ctrl = self._internal_controller
        if ctrl is not None:
            ctrl.cancel()

    def get_status(self) -> str:
        """获取当前扫描任务状态。"""
        ctrl = self._internal_controller
        if ctrl is not None:
            return ctrl.get_status()
        return "waiting"

    def get_statistics(self) -> Optional[Dict[str, int]]:
        """获取最近一次扫描的统计数据。"""
        if self._statistics is not None:
            return self._statistics.to_dict()
        return None

    # ---- 单端口扫描 ----

    def scan_port(self, host: str, port: int) -> TCPConnectScanResult:
        """扫描单个 TCP 端口（同步方法）。

        Args:
            host: 目标主机 IP 或域名
            port: 目标端口号

        Returns:
            TCPConnectScanResult: 扫描结果对象
        """
        if port < 1 or port > 65535:
            return TCPConnectScanResult(
                host=host,
                port=port,
                status="error",
                error_code=None,
                error_message="端口号必须在 1～65535 之间",
                response_time_ms=None,
            )

        sock = None
        start_time = time.perf_counter()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            result_code = sock.connect_ex((host, port))
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            if result_code == 0:
                return TCPConnectScanResult(
                    host=host,
                    port=port,
                    status="open",
                    error_code=0,
                    error_message="连接成功",
                    response_time_ms=round(elapsed_ms, 2),
                )

            # 只有 ECONNREFUSED 才判定为端口关闭
            if result_code in _CLOSED_CODES:
                return TCPConnectScanResult(
                    host=host,
                    port=port,
                    status="closed",
                    error_code=result_code,
                    error_message="连接被拒绝（端口关闭）",
                    response_time_ms=None,
                )

            # 超时 / 主机不可达 → 被过滤
            if result_code in _FILTERED_CODES:
                return TCPConnectScanResult(
                    host=host,
                    port=port,
                    status="filtered",
                    error_code=result_code,
                    error_message=f"连接超时或主机不可达 (errno={result_code})",
                    response_time_ms=None,
                )

            # 网络不可达 / 资源暂不可用 / 权限 / 其他未知错误
            return TCPConnectScanResult(
                host=host,
                port=port,
                status="error",
                error_code=result_code,
                error_message=f"连接错误 (errno={result_code})",
                response_time_ms=None,
            )

        except socket.gaierror as exc:
            return TCPConnectScanResult(
                host=host,
                port=port,
                status="error",
                error_code=exc.errno,
                error_message=f"地址解析错误：{exc}",
                response_time_ms=None,
            )

        except ConnectionRefusedError as exc:
            return TCPConnectScanResult(
                host=host,
                port=port,
                status="closed",
                error_code=exc.errno if exc.errno else None,
                error_message="连接被拒绝（端口关闭）",
                response_time_ms=None,
            )

        except socket.timeout as exc:
            return TCPConnectScanResult(
                host=host,
                port=port,
                status="filtered",
                error_code=None,
                error_message=f"连接超时：{exc}",
                response_time_ms=None,
            )

        except PermissionError as exc:
            return TCPConnectScanResult(
                host=host,
                port=port,
                status="error",
                error_code=exc.errno if exc.errno else None,
                error_message=f"权限不足：{exc}",
                response_time_ms=None,
            )

        except OSError as exc:
            return TCPConnectScanResult(
                host=host,
                port=port,
                status="error",
                error_code=exc.errno if exc.errno else None,
                error_message=f"系统错误：{exc}",
                response_time_ms=None,
            )

        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    # ---- 批量端口扫描（底层接口） ----

    def scan_ports(
        self,
        host: str,
        ports: List[int],
        max_workers: Optional[int] = None,
        controller: Optional[ScanTaskController] = None,
        status_callback: Optional[Callable[[str], None]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[TCPConnectScanResult]:
        """扫描多个 TCP 端口（底层接口）。

        Args:
            host: 目标主机 IP 或域名
            ports: 端口列表（会自动去重排序）
            max_workers: 覆盖扫描器的默认并发数（可选）
            controller: 外部控制器（可选）
            status_callback: 状态变化回调（可选）
            progress_callback: 进度回调，兼容两种签名：
                (completed, total)           —— 旧接口
                (completed, total, result)   —— 新接口（推荐）

        Returns:
            List[TCPConnectScanResult]: 去重排序后的扫描结果

        Raises:
            ValueError: 参数不合法
            RuntimeError: 同一扫描器实例已有扫描任务在运行
        """
        # ---- 端口列表校验 ----
        if not isinstance(ports, list):
            raise ValueError("ports 必须是整数列表")
        if any(not isinstance(p, int) or isinstance(p, bool) for p in ports):
            raise ValueError("端口列表中只能包含整数")

        actual_workers = max_workers if max_workers is not None else self._max_workers
        if actual_workers < 1 or actual_workers > 500:
            raise ValueError("max_workers 必须在 1～500 之间")

        if not self._scan_lock.acquire(blocking=False):
            raise RuntimeError("当前扫描器实例正在执行扫描任务，请等待完成后再开始新任务")

        try:
            return self._scan_ports_impl(
                host=host,
                ports=ports,
                max_workers=actual_workers,
                controller=controller,
                status_callback=status_callback,
                progress_callback=progress_callback,
            )
        finally:
            self._scan_lock.release()

    def _scan_ports_impl(
        self,
        host: str,
        ports: List[int],
        max_workers: int,
        controller: Optional[ScanTaskController],
        status_callback: Optional[Callable[[str], None]],
        progress_callback: Optional[Callable[[int, int], None]],
    ) -> List[TCPConnectScanResult]:
        """scan_ports() 的内部实现。"""

        unique_ports = sorted(set(ports))
        total_count = len(unique_ports)

        # 设置控制器
        if controller is not None:
            ctrl = controller
            if status_callback is not None:
                ctrl.set_status_callback(status_callback)
            self._internal_controller = ctrl
        else:
            ctrl = ScanTaskController()
            if status_callback is not None:
                ctrl.set_status_callback(status_callback)
            self._internal_controller = ctrl

        ctrl.reset()
        ctrl.start()

        # 数据结构
        future_to_port: Dict[Future, int] = {}
        results_by_port: Dict[int, TCPConnectScanResult] = {}
        ports_iter = iter(unique_ports)
        ports_exhausted = False

        # 实际 pending 数
        max_pending = min(self._max_pending, max_workers)
        if max_pending < 1:
            max_pending = 1
        if total_count > 0 and max_pending > total_count:
            max_pending = total_count

        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                while not (ports_exhausted and not future_to_port):
                    # 取消检查
                    if ctrl.is_cancelled():
                        self._handle_cancellation(
                            future_to_port=future_to_port,
                            results_by_port=results_by_port,
                            host=host,
                            ports_iter=ports_iter,
                            unique_ports=unique_ports,
                            progress_callback=progress_callback,
                            total_count=total_count,
                        )
                        break

                    # 暂停等待（使用 Condition 避免忙等待）
                    ctrl.wait_if_paused()

                    if ctrl.is_cancelled():
                        self._handle_cancellation(
                            future_to_port=future_to_port,
                            results_by_port=results_by_port,
                            host=host,
                            ports_iter=ports_iter,
                            unique_ports=unique_ports,
                            progress_callback=progress_callback,
                            total_count=total_count,
                        )
                        break

                    # 提交新任务
                    while len(future_to_port) < max_pending and not ports_exhausted:
                        if ctrl.is_cancelled() or ctrl.is_paused():
                            break
                        try:
                            port = next(ports_iter)
                        except StopIteration:
                            ports_exhausted = True
                            break

                        future = executor.submit(self.scan_port, host, port)
                        future_to_port[future] = port

                    # 收集已完成的任务
                    if future_to_port:
                        done, _ = concurrent.futures.wait(
                            list(future_to_port.keys()),
                            timeout=0.1,
                            return_when=concurrent.futures.FIRST_COMPLETED,
                        )

                        for future in done:
                            port = future_to_port.pop(future, None)
                            if port is None:
                                continue
                            if port in results_by_port:
                                continue

                            result = self._safe_get_result(future, host, port)
                            results_by_port[port] = result

                            _invoke_progress_callback(
                                progress_callback,
                                len(results_by_port),
                                total_count,
                                result,
                            )

            # 线程池退出后，确保所有端口都有结果
            if ctrl.is_cancelled():
                self._finalize_cancelled_results(
                    future_to_port=future_to_port,
                    results_by_port=results_by_port,
                    host=host,
                    unique_ports=unique_ports,
                )

        except Exception:
            ctrl.mark_failed()
            raise

        # 构建最终结果
        final_results = self._build_final_results(unique_ports, results_by_port)

        # 统计
        self._statistics = ScanStatistics.from_results(final_results)

        # 最终状态
        if ctrl.is_cancelled():
            ctrl._set_status("cancelled")
        else:
            ctrl.mark_completed()

        return final_results

    # ---- 取消处理 ----

    def _handle_cancellation(
        self,
        future_to_port: Dict[Future, int],
        results_by_port: Dict[int, TCPConnectScanResult],
        host: str,
        ports_iter: iter,
        unique_ports: List[int],
        progress_callback: Optional[Callable[[int, int], None]],
        total_count: int,
    ) -> None:
        """处理取消：取消未开始的任务，等待已运行的任务自然完成。"""

        still_running: Dict[Future, int] = {}
        for future, port in list(future_to_port.items()):
            if future.cancel():
                if port not in results_by_port:
                    results_by_port[port] = TCPConnectScanResult(
                        host=host,
                        port=port,
                        status="cancelled",
                        error_code=None,
                        error_message="扫描已被用户取消",
                        response_time_ms=None,
                    )
                    _invoke_progress_callback(
                        progress_callback,
                        len(results_by_port),
                        total_count,
                        results_by_port[port],
                    )
            else:
                still_running[future] = port
            future_to_port.pop(future, None)

        # 等待已在运行的任务自然完成
        if still_running:
            for future in as_completed(list(still_running.keys())):
                port = still_running.get(future)
                if port is None or port in results_by_port:
                    continue

                result = self._safe_get_result(future, host, port)
                results_by_port[port] = result

                _invoke_progress_callback(
                    progress_callback,
                    len(results_by_port),
                    total_count,
                    result,
                )

        # 将尚未提交的端口标记为 cancelled
        submitted_or_done = set(results_by_port.keys())
        for port in unique_ports:
            if port not in submitted_or_done:
                results_by_port[port] = TCPConnectScanResult(
                    host=host,
                    port=port,
                    status="cancelled",
                    error_code=None,
                    error_message="扫描已被用户取消",
                    response_time_ms=None,
                )
                _invoke_progress_callback(
                    progress_callback,
                    len(results_by_port),
                    total_count,
                    results_by_port[port],
                )

    def _finalize_cancelled_results(
        self,
        future_to_port: Dict[Future, int],
        results_by_port: Dict[int, TCPConnectScanResult],
        host: str,
        unique_ports: List[int],
    ) -> None:
        """线程池退出后，确保所有端口都有结果。"""
        for future, port in list(future_to_port.items()):
            if port not in results_by_port:
                result = self._safe_get_result(future, host, port)
                results_by_port[port] = result
            future_to_port.pop(future, None)

        for port in unique_ports:
            if port not in results_by_port:
                results_by_port[port] = TCPConnectScanResult(
                    host=host,
                    port=port,
                    status="cancelled",
                    error_code=None,
                    error_message="扫描已被用户取消",
                    response_time_ms=None,
                )

    # ---- 辅助方法 ----

    @staticmethod
    def _safe_get_result(
        future: Future, host: str, port: int
    ) -> TCPConnectScanResult:
        """安全地从 Future 获取结果，不传播异常。"""
        try:
            return future.result()
        except concurrent.futures.CancelledError:
            return TCPConnectScanResult(
                host=host,
                port=port,
                status="cancelled",
                error_code=None,
                error_message="扫描已被用户取消",
                response_time_ms=None,
            )
        except Exception as exc:
            return TCPConnectScanResult(
                host=host,
                port=port,
                status="error",
                error_code=None,
                error_message=f"扫描异常：{exc}",
                response_time_ms=None,
            )

    @staticmethod
    def _build_final_results(
        unique_ports: List[int],
        results_by_port: Dict[int, TCPConnectScanResult],
    ) -> List[TCPConnectScanResult]:
        """根据端口顺序构建最终结果列表，每个端口只出现一次。"""
        return [results_by_port[p] for p in unique_ports if p in results_by_port]

    # ---- GUI 扫描接口 ----

    def scan_ports_for_ui(
        self,
        host: str,
        ports: List[int],
        host_status: str = "",
        max_workers: Optional[int] = None,
        controller: Optional[ScanTaskController] = None,
        status_callback: Optional[Callable[[str], None]] = None,
        progress_callback: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
        complete_callback: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
        icmp_status_code: str = "offline",
    ) -> List[Dict[str, Any]]:
        """面向 GUI 的扫描接口，返回组长要求的 JSON 格式。

        最终主机状态由 resolve_final_host_status() 综合 ICMP 与 TCP 结果判定，
        TCP 出现 open 或真正的 closed 时优先显示在线，不会被外部 host_status 覆盖。

        Args:
            host: 目标主机 IP
            ports: 端口列表
            host_status: （保留兼容）只作初始状态参考，不覆盖 TCP 明确响应
            max_workers: 覆盖默认并发数（可选）
            controller: 外部控制器（可选）
            status_callback: 状态变化回调（可选）
            progress_callback: GUI 进度回调 (completed, total, result_dict)（可选）
            complete_callback: 完成回调（可选）
            icmp_status_code: ICMP 初始状态码，"online" 或 "offline"

        Returns:
            List[Dict[str, Any]]: 严格包含 ip/host_status/method/port/port_status/service
        """
        # 标记：扫描过程中是否已发现 open 或 closed → 用于实时进度中的暂定 host_status
        _seen_responsive: List[bool] = [False]

        # 底层进度 → GUI 进度包装（传递实际 result_dict）
        def _ui_progress(completed: int, total: int, result: TCPConnectScanResult) -> None:
            if progress_callback is None:
                return
            # 更新实时发现标记
            if result.status in ("open", "closed"):
                _seen_responsive[0] = True
            # 实时阶段的暂定 host_status
            if icmp_status_code == "online" or _seen_responsive[0]:
                provisional = "在线"
            else:
                provisional = "离线"
            ui_dict = result_to_ui_dict(result, provisional)
            try:
                progress_callback(completed, total, ui_dict)
            except Exception:
                pass

        # 执行 TCP 扫描
        raw_results = self.scan_ports(
            host=host,
            ports=ports,
            max_workers=max_workers,
            controller=controller,
            status_callback=status_callback,
            progress_callback=_ui_progress if progress_callback else None,
        )

        # 综合判断最终主机状态（永不强制使用外部 host_status）
        if host_status == "在线":
            initial_code = "online"
        else:
            initial_code = icmp_status_code
        final_status_code = resolve_final_host_status(initial_code, raw_results)
        final_host_status = "在线" if final_status_code == "online" else "离线"

        ui_results = results_to_ui_dicts(raw_results, final_host_status)

        if complete_callback is not None:
            try:
                complete_callback(ui_results)
            except Exception:
                pass

        return ui_results


# ============================================================================
# 打印函数
# ============================================================================

def print_scan_results(
    results: List[TCPConnectScanResult],
    ui_results: Optional[List[Dict[str, Any]]] = None,
    profile_key: Optional[str] = None,
    max_workers: Optional[int] = None,
    status: Optional[str] = None,
    statistics: Optional[Dict[str, int]] = None,
) -> None:
    """打印扫描结果（仅用于命令行调试）。

    Args:
        results: 底层 TCPConnectScanResult 列表
        ui_results: GUI 格式结果列表（可选）
        profile_key: 扫描模式（可选）
        max_workers: 实际并发数（可选）
        status: 任务状态（可选）
        statistics: 扫描统计（可选）
    """
    print()
    print("=" * 85)


def print_fingerprint_debug_results(
    host: str,
    open_ports: List[int],
    timeout: float = 3.0,
) -> None:
    """仅用于 __main__ 调试联动，不写入扫描器正式返回结果。"""
    unique_open_ports = sorted(set(open_ports))

    print()
    print("【Fingerprint 调试验证】")

    if not unique_open_ports:
        print("  未发现开放端口，跳过服务指纹识别。")
        return

    try:
        from .service_fingerprint import scan_services
    except ImportError:
        from service_fingerprint import scan_services

    print(f"  对开放端口做额外指纹识别验证：{unique_open_ports}")

    try:
        fingerprint_results = scan_services(host, unique_open_ports, timeout=timeout)
    except Exception as exc:
        print(f"  服务指纹识别失败：{exc}")
        return

    print("-" * 110)
    print(
        f"{'Host':<18}{'Port':<8}{'Open':<8}"
        f"{'Service':<18}{'Version':<20}{'Probe':<16}{'Detail'}"
    )
    print("-" * 110)

    for item in fingerprint_results:
        service = item.service or "未知"
        version = item.version or "-"
        probe = item.probe or "-"
        detail = item.detail or ""
        print(
            f"{item.host:<18}{item.port:<8}{str(item.open):<8}"
            f"{service:<18}{version:<20}{probe:<16}{detail}"
        )

    print("-" * 110)
    print("  TCP Connect 端口扫描结果")
    print("=" * 85)

    if profile_key or max_workers or status:
        print()
        print("【扫描信息】")
        if profile_key:
            info = SCAN_PROFILES.get(profile_key, {})
            name = info.get("display_name", profile_key)
            print(f"  扫描模式：{name} ({profile_key})")
        if max_workers:
            print(f"  实际并发数：{max_workers}")
        if status:
            print(f"  任务状态：{status}")

    if statistics:
        print()
        print("【扫描统计】")
        print(f"  总端口数：{statistics.get('total_ports', 0)}")
        print(f"  开放：{statistics.get('open_ports', 0)}")
        print(f"  关闭：{statistics.get('closed_ports', 0)}")
        print(f"  被过滤：{statistics.get('filtered_ports', 0)}")
        print(f"  错误：{statistics.get('error_ports', 0)}")
        print(f"  已取消：{statistics.get('cancelled_ports', 0)}")

    if results:
        print()
        print("【底层 TCPConnectScanResult 表格】")
        print("-" * 85)
        print(
            f"{'Host':<18}{'Port':<8}{'Status':<12}"
            f"{'ErrCode':<10}{'Resp(ms)':<12}{'Message'}"
        )
        print("-" * 85)

        for r in results:
            ec = str(r.error_code) if r.error_code is not None else "-"
            rt = f"{r.response_time_ms:.1f}" if r.response_time_ms is not None else "-"
            msg = (r.error_message or "")[:35]
            print(f"{r.host:<18}{r.port:<8}{r.status:<12}{ec:<10}{rt:<12}{msg}")
        print("-" * 85)

    if ui_results:
        print()
        print("【GUI 字典列表 (scan_ports_for_ui 返回)】")
        import json as _json
        print(_json.dumps(ui_results, ensure_ascii=False, indent=2))

    print()
    print("=" * 85)


# ============================================================================
# 调试入口
# ============================================================================

def print_scan_results(
    results: List[TCPConnectScanResult],
    ui_results: Optional[List[Dict[str, Any]]] = None,
    profile_key: Optional[str] = None,
    max_workers: Optional[int] = None,
    status: Optional[str] = None,
    statistics: Optional[Dict[str, int]] = None,
) -> None:
    """打印扫描结果，仅用于命令行调试。"""
    print()
    print("=" * 85)
    print("  TCP Connect 端口扫描结果")
    print("=" * 85)

    if profile_key or max_workers or status:
        print()
        print("【扫描信息】")
        if profile_key:
            info = SCAN_PROFILES.get(profile_key, {})
            name = info.get("display_name", profile_key)
            print(f"  扫描模式：{name} ({profile_key})")
        if max_workers:
            print(f"  实际并发数：{max_workers}")
        if status:
            print(f"  任务状态：{status}")

    if statistics:
        print()
        print("【扫描统计】")
        print(f"  总端口数：{statistics.get('total_ports', 0)}")
        print(f"  开放：{statistics.get('open_ports', 0)}")
        print(f"  关闭：{statistics.get('closed_ports', 0)}")
        print(f"  被过滤：{statistics.get('filtered_ports', 0)}")
        print(f"  错误：{statistics.get('error_ports', 0)}")
        print(f"  已取消：{statistics.get('cancelled_ports', 0)}")

    if results:
        print()
        print("【底层 TCPConnectScanResult 表格】")
        print("-" * 85)
        print(
            f"{'Host':<18}{'Port':<8}{'Status':<12}"
            f"{'ErrCode':<10}{'Resp(ms)':<12}{'Message'}"
        )
        print("-" * 85)

        for result in results:
            error_code = str(result.error_code) if result.error_code is not None else "-"
            response_time = (
                f"{result.response_time_ms:.1f}"
                if result.response_time_ms is not None
                else "-"
            )
            message = (result.error_message or "")[:35]
            print(
                f"{result.host:<18}{result.port:<8}{result.status:<12}"
                f"{error_code:<10}{response_time:<12}{message}"
            )
        print("-" * 85)

    if ui_results:
        print()
        print("【GUI 字典列表 (scan_ports_for_ui 返回)】")
        import json as _json
        print(_json.dumps(ui_results, ensure_ascii=False, indent=2))

    print()
    print("=" * 85)


def print_fingerprint_debug_results(
    host: str,
    open_ports: List[int],
    timeout: float = 3.0,
) -> None:
    """仅用于 __main__ 调试联动，不写入扫描器正式返回结果。"""
    unique_open_ports = sorted(set(open_ports))

    print()
    print("【Fingerprint 调试验证】")

    if not unique_open_ports:
        print("  未发现开放端口，跳过服务指纹识别。")
        return

    try:
        from .service_fingerprint import scan_services
    except ImportError:
        from service_fingerprint import scan_services

    print(f"  对开放端口做额外指纹识别验证：{unique_open_ports}")

    try:
        fingerprint_results = scan_services(host, unique_open_ports, timeout=timeout)
    except Exception as exc:
        print(f"  服务指纹识别失败：{exc}")
        return

    print("-" * 110)
    print(
        f"{'Host':<18}{'Port':<8}{'Open':<8}"
        f"{'Service':<18}{'Version':<20}{'Probe':<16}{'Detail'}"
    )
    print("-" * 110)

    for item in fingerprint_results:
        service = item.service or "未知"
        version = item.version or "-"
        probe = item.probe or "-"
        detail = item.detail or ""
        print(
            f"{item.host:<18}{item.port:<8}{str(item.open):<8}"
            f"{service:<18}{version:<20}{probe:<16}{detail}"
        )

    print("-" * 110)


if __name__ == "__main__":
    """单独运行本文件用于调试。

    正式接入时，请使用 scan_ports_for_ui() 获取 GUI 结果，
    并通过 ICMP 模块获取 host_status。

    正确调用流程（推荐方案 A：调用层手动控制）：
        from .host_discovery import is_host_alive

        # 1. ICMP 探测
        icmp_alive = is_host_alive(target_ip)
        icmp_code = "online" if icmp_alive else "offline"

        # 2. TCP 扫描
        raw_results = scanner.scan_ports(target_ip, ports)

        # 3. 综合判断
        final_code = resolve_final_host_status(icmp_code, raw_results)
        final_status = "在线" if final_code == "online" else "离线"

        # 4. 转换 GUI
        ui_results = results_to_ui_dicts(raw_results, final_status)

    或使用 scan_ports_for_ui 自动综合（方案 B）：
        ui_results = scanner.scan_ports_for_ui(
            host=target_ip, ports=[...],
            icmp_status_code=icmp_code,
        )
    """

    import json

    target_host = "192.168.45.128"
    port_input = "21,22,80,443,3306,3389,8080"
    timeout = 1.0

    # ================================================================
    # 第一步：通过 ICMP 模块获取初始状态码
    # ================================================================
    print("╔══════════════════════════════════════════════════╗")
    print("║       TCP Connect 扫描器 —— 调试模式             ║")
    print("╚══════════════════════════════════════════════════╝")
    print()
    print(f"  目标主机：{target_host}")
    print(f"  扫描端口：{port_input}")
    print(f"  超时时间：{timeout}s")
    print()

    # ----- ICMP 主机探测（仅获取初始状态码） -----
    icmp_status_code: str = "offline"
    try:
        from .host_discovery import is_host_alive
    except ImportError:
        from host_discovery import is_host_alive
    try:
        print("  [ICMP] 正在探测主机是否在线 ...")
        alive = is_host_alive(target_host, timeout_ms=1000)
        icmp_status_code = "online" if alive else "offline"
        icmp_display = "在线" if alive else "离线"
        print(f"  [ICMP] 探测结果：{icmp_display}")
    except Exception as exc:
        print(f'  [ICMP] 探测异常：{exc}，ICMP 初始状态设为 offline')
        icmp_status_code = "offline"

    print()

    try:
        ports = parse_ports(port_input)
    except ValueError as e:
        print(f"端口输入错误：{e}")
        exit(1)

    # ================================================================
    # 第二步：TCP Connect 扫描 + 综合判断最终主机状态
    # ================================================================

    # ---- 测试 1：方案 A（推荐）—— 调用层手动控制 ----
    print(">>> 测试 1：方案 A —— 先 scan_ports 再综合判断")
    try:
        scanner = TCPConnectScanner.from_profile(profile_key="normal", timeout=timeout)

        # 先执行底层扫描
        raw_results = scanner.scan_ports(host=target_host, ports=ports)

        # 综合 ICMP 和 TCP 结果计算最终状态
        final_code = resolve_final_host_status(icmp_status_code, raw_results)
        final_host_status = "在线" if final_code == "online" else "离线"

        # 调试提示
        if icmp_status_code == "offline" and final_code == "online":
            print("  [TCP] 检测到目标主机有明确响应")
        print(f"  最终主机状态：{final_host_status}")

        # 转换 GUI 结果
        ui_results = results_to_ui_dicts(raw_results, final_host_status)

        print_scan_results(
            results=raw_results,
            ui_results=ui_results,
            profile_key="normal",
            max_workers=scanner.max_workers,
            status=scanner.get_status(),
            statistics=scanner.get_statistics(),
        )

        # 仅在调试时联动 fingerprint，便于验证服务识别是否完善。
        # 不修改 scan_port()/scan_ports()/scan_ports_for_ui() 的正式返回结构。
        # 仅在调试时联动 fingerprint，便于验证服务识别是否完善。
        # 不修改 scan_port()/scan_ports()/scan_ports_for_ui() 的正式返回结构。
        open_ports = [result.port for result in raw_results if result.status == "open"]
        open_ports = [result.port for result in raw_results if result.status == "open"]
        print_fingerprint_debug_results(
            host=target_host,
            open_ports=open_ports,
            timeout=timeout,
        )

    except Exception as e:
        print(f"扫描出错：{e}")

    # ---- 测试 2：方案 B —— scan_ports_for_ui 自动综合 ----
    print()
    print(">>> 测试 2：方案 B —— scan_ports_for_ui 自动综合")
    try:
        controller = ScanTaskController()

        scanner2 = TCPConnectScanner.from_profile(profile_key="slow", timeout=timeout)

        ui_results2 = scanner2.scan_ports_for_ui(
            host=target_host,
            ports=ports,
            icmp_status_code=icmp_status_code,
            controller=controller,
        )

        # 调试提示
        if icmp_status_code == "offline":
            has_response = any(
                r.get("port_status") in {"开放", "关闭"}
                for r in ui_results2
            )
            if has_response:
                print("  [TCP] 检测到目标主机有明确响应")

        # 显示最终状态（从第一条结果取）
        final_display = ui_results2[0]["host_status"] if ui_results2 else "离线"
        print(f"  最终主机状态：{final_display}")
        print(f"  结果数量：{len(ui_results2)}")
        stats = scanner2.get_statistics()
        if stats:
            print(f"  统计：total={stats['total_ports']} open={stats['open_ports']}")

    except Exception as e:
        print(f"扫描出错：{e}")

    # ---- 简单自检 ----
    print()
    print(">>> 简单自检")
    checks = []

    try:
        assert resolve_max_workers("slow") == 20, "slow != 20"
        assert resolve_max_workers("normal") == 100, "normal != 100"
        assert resolve_max_workers("fast") == 300, "fast != 300"
        assert resolve_max_workers("custom", 150) == 150, "custom 150 != 150"
        checks.append("✅ 扫描模式预设正确")
    except Exception as e:
        checks.append(f"❌ 扫描模式检查失败：{e}")

    try:
        resolve_max_workers("custom", 0)
        checks.append("❌ custom=0 应报错但未报错")
    except ValueError:
        checks.append("✅ custom=0 正确报错")

    try:
        resolve_max_workers("custom", 501)
        checks.append("❌ custom=501 应报错但未报错")
    except ValueError:
        checks.append("✅ custom=501 正确报错")

    try:
        resolve_max_workers("unknown")
        checks.append("❌ 未知模式应报错但未报错")
    except ValueError:
        checks.append("✅ 未知模式正确报错")

    try:
        results_to_ui_dicts([], "非法状态")
        checks.append("❌ 非法 host_status 应报错但未报错")
    except ValueError:
        checks.append("✅ 非法 host_status 正确报错")

    try:
        TCPConnectScanner(timeout=0)
        checks.append("❌ timeout<=0 应报错但未报错")
    except ValueError:
        checks.append("✅ timeout<=0 正确报错")

    try:
        TCPConnectScanner(max_workers=0)
        checks.append("❌ max_workers<1 应报错但未报错")
    except ValueError:
        checks.append("✅ max_workers<1 正确报错")

    try:
        TCPConnectScanner(max_workers=501)
        checks.append("❌ max_workers>500 应报错但未报错")
    except ValueError:
        checks.append("✅ max_workers>500 正确报错")

    # ---- 新增自检：错误码分类 ----
    # ECONNREFUSED → closed
    ecr_code = getattr(errno, "ECONNREFUSED", 10061)
    if ecr_code in _CLOSED_CODES:
        checks.append(f"✅ ECONNREFUSED({ecr_code}) → closed")
    else:
        checks.append(f"❌ ECONNREFUSED({ecr_code}) 未归类为 closed")

    # EAGAIN(11) → 不应归类为 closed
    eagain_code = getattr(errno, "EAGAIN", 11)
    if eagain_code not in _CLOSED_CODES:
        checks.append(f"✅ EAGAIN({eagain_code}) 不在 closed_codes 中")
    else:
        checks.append(f"❌ EAGAIN({eagain_code}) 被误归类为 closed")

    # ---- 新增自检：主机状态综合 ----
    # TCP open → online
    open_results = [TCPConnectScanResult("x", 80, "open", 0, "ok", None)]
    assert resolve_final_host_status("offline", open_results) == "online"
    checks.append("✅ TCP open 将最终主机状态修正为在线")

    # 真正的 closed → online
    closed_results = [TCPConnectScanResult("x", 80, "closed", ecr_code, "拒绝", None)]
    assert resolve_final_host_status("offline", closed_results) == "online"
    checks.append("✅ TCP 真正的 closed 将最终主机状态修正为在线")

    # filtered + error 不修正
    mixed_results = [
        TCPConnectScanResult("x", 80, "filtered", 10060, "", None),
        TCPConnectScanResult("x", 443, "error", 11, "", None),
    ]
    assert resolve_final_host_status("offline", mixed_results) == "offline"
    checks.append("✅ filtered/error 不单独将主机修正为在线")

    # ICMP online → online
    assert resolve_final_host_status("online", []) == "online"
    checks.append("✅ ICMP online → online")

    # ---- 新增自检：统计校验 ----
    if ui_results:
        stats = scanner.get_statistics()
        if stats:
            total = stats.get("total_ports", 0)
            summed = (
                stats.get("open_ports", 0)
                + stats.get("closed_ports", 0)
                + stats.get("filtered_ports", 0)
                + stats.get("error_ports", 0)
                + stats.get("cancelled_ports", 0)
            )
            if total == summed:
                checks.append("✅ 统计各项之和等于 total_ports")
            else:
                checks.append(f"❌ 统计项之和({summed}) != total_ports({total})")

    # ---- 新增自检：边界情况 ----
    # 空端口列表
    empty_results = scanner.scan_ports(host=target_host, ports=[])
    if empty_results == []:
        checks.append("✅ 空端口列表返回空列表")
    else:
        checks.append("❌ 空端口列表未返回空列表")

    # 非列表 ports
    try:
        scanner.scan_ports(host=target_host, ports="not_a_list")
        checks.append("❌ 非列表 ports 应报错但未报错")
    except ValueError:
        checks.append("✅ 非列表 ports 正确抛出 ValueError")

    # ---- 新增自检：GUI 进度回调不传空字典 ----
    _captured: List[Dict[str, Any]] = []

    def _test_gui_cb(completed: int, total: int, result_dict: Dict[str, Any]) -> None:
        _captured.append(result_dict)

    scanner3 = TCPConnectScanner.from_profile(profile_key="normal", timeout=timeout)
    ui3 = scanner3.scan_ports_for_ui(
        host=target_host,
        ports=[80],
        icmp_status_code=icmp_status_code,
        progress_callback=_test_gui_cb,
    )
    if _captured and all(isinstance(d, dict) and d for d in _captured):
        checks.append("✅ GUI 进度回调收到非空 result_dict")
    else:
        checks.append("❌ GUI 进度回调收到空字典或无回调")

    # 检查 result_dict 包含必要字段
    if _captured:
        req = {"ip", "host_status", "method", "port", "port_status", "service"}
        ok = all(set(d.keys()) == req for d in _captured)
        checks.append("✅ GUI 进度回调字段完整" if ok else "❌ GUI 进度回调字段不完整")

    # 检查 host_status 覆盖问题：传入离线，但 TCP 有响应时必须在线
    # 用本地回环地址确保有可靠响应
    local_scanner = TCPConnectScanner.from_profile(profile_key="normal", timeout=timeout)
    scan4_results = local_scanner.scan_ports_for_ui(
        host="127.0.0.1",
        ports=[443],
        host_status="离线",
    )
    if scan4_results:
        actual_status = scan4_results[0].get("host_status")
        actual_port_status = scan4_results[0].get("port_status")
        if actual_port_status in ("开放", "关闭") and actual_status == "离线":
            checks.append("❌ host_status=离线 错误覆盖了 TCP 响应")
        elif actual_port_status in ("开放", "关闭") and actual_status == "在线":
            checks.append("✅ 传入 host_status=离线 不会覆盖 TCP 明确响应")
        else:
            checks.append("⚠️ 无法验证 host_status 覆盖（端口无响应）")
    else:
        checks.append("⚠️ 无法验证 host_status 覆盖（无结果）")

    # ---- 原有 GUI 字段校验 ----
        required = {"ip", "host_status", "method", "port", "port_status", "service"}
        first = ui_results[0]
        if set(first.keys()) == required:
            checks.append("✅ GUI 返回字段完全正确")
        else:
            extra = set(first.keys()) - required
            missing = required - set(first.keys())
            checks.append(f"❌ GUI 字段：多余={extra} 缺少={missing}")

        try:
            json.dumps(ui_results, ensure_ascii=False)
            checks.append("✅ GUI 结果可 JSON 序列化")
        except Exception:
            checks.append("❌ GUI 结果无法 JSON 序列化")

    for check in checks:
        print(f"  {check}")

    print()
    print("调试完成。")

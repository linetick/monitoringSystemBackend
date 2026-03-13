import socket
import time
from datetime import datetime, timezone
from typing import Optional

import psutil
from fastapi import HTTPException

from .config import settings


STATUS_OK = "ok"
STATUS_WARNING = "warning"
STATUS_CRITICAL = "critical"
PROCESS_ACTION_TIMEOUT_SECONDS = 3
PROCESS_STATUS_ACCESS_DENIED = "access_denied"
PROCESS_STATUS_UNKNOWN = "unknown"
PROCESS_STATUS_ZOMBIE = "zombie"
PROCESS_SORT_FIELDS = {"pid", "name", "cpu", "mem", "status", "owner"}


def _read_hostname_file(path: Optional[str]) -> Optional[str]:
    if not path:
        return None

    try:
        with open(path, "r", encoding="utf-8") as file:
            hostname = file.read().strip()
            return hostname or None
    except OSError:
        return None


def _resolve_hostname() -> str:
    if settings.server_name:
        return settings.server_name

    hostname_paths = [
        settings.metrics_hostname_path,
        "/host/proc/1/root/etc/hostname",
        "/host/proc/sys/kernel/hostname",
    ]
    checked_paths = []
    for hostname_path in hostname_paths:
        if not hostname_path or hostname_path in checked_paths:
            continue
        checked_paths.append(hostname_path)
        hostname = _read_hostname_file(hostname_path)
        if hostname:
            return hostname

    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def _resolve_disk_usage():
    disk_paths = [settings.metrics_disk_path, "/"]
    checked_paths = []

    for disk_path in disk_paths:
        if not disk_path or disk_path in checked_paths:
            continue
        checked_paths.append(disk_path)
        try:
            return psutil.disk_usage(disk_path)
        except OSError:
            continue

    raise RuntimeError("Unable to resolve disk usage path")


def _evaluate_metric(
    label: str,
    value: float,
    warning_threshold: float,
    critical_threshold: float,
):
    if value >= critical_threshold:
        return STATUS_CRITICAL, f"{label} is critical: {value:.1f}%"
    if value >= warning_threshold:
        return STATUS_WARNING, f"{label} is high: {value:.1f}%"
    return STATUS_OK, None


def _build_metrics_status(cpu_percent: float, mem_percent: float, disk_percent: float):
    alerts = []
    statuses = []
    metric_checks = [
        (
            "CPU usage",
            cpu_percent,
            settings.cpu_warning_threshold,
            settings.cpu_critical_threshold,
        ),
        (
            "Memory usage",
            mem_percent,
            settings.mem_warning_threshold,
            settings.mem_critical_threshold,
        ),
        (
            "Disk usage",
            disk_percent,
            settings.disk_warning_threshold,
            settings.disk_critical_threshold,
        ),
    ]

    for label, value, warning_threshold, critical_threshold in metric_checks:
        metric_status, alert = _evaluate_metric(
            label,
            value,
            warning_threshold,
            critical_threshold,
        )
        statuses.append(metric_status)
        if alert:
            alerts.append(alert)

    if STATUS_CRITICAL in statuses:
        return STATUS_CRITICAL, alerts
    if STATUS_WARNING in statuses:
        return STATUS_WARNING, alerts
    return STATUS_OK, alerts


def get_server_metrics():
    cpu_percent = psutil.cpu_percent(interval=settings.metrics_cpu_interval_seconds)
    mem = psutil.virtual_memory()
    disk = _resolve_disk_usage()
    status, alerts = _build_metrics_status(cpu_percent, mem.percent, disk.percent)

    return {
        "hostname": _resolve_hostname(),
        "cpu_percent": round(cpu_percent, 2),
        "mem_percent": round(mem.percent, 2),
        "disk_percent": round(disk.percent, 2),
        "last_update": datetime.now(timezone.utc),
        "status": status,
        "alerts": alerts,
    }

def _normalize_process_name(pid: int, name: Optional[str]) -> str:
    return name or f"pid-{pid}"


def _normalize_process_owner(owner: Optional[str]) -> str:
    return owner or PROCESS_STATUS_UNKNOWN


def _prime_process_cpu_counters(processes) -> None:
    # psutil returns meaningful per-process CPU values only after the first read.
    for proc in processes:
        try:
            proc.cpu_percent(interval=None)
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue

    if settings.process_cpu_interval_seconds > 0:
        time.sleep(settings.process_cpu_interval_seconds)


def _build_process_info(proc: psutil.Process):
    info = proc.info
    pid = info["pid"]
    process_name = _normalize_process_name(pid, info.get("name"))
    process_owner = _normalize_process_owner(info.get("username"))
    process_status = info.get("status") or PROCESS_STATUS_UNKNOWN

    try:
        with proc.oneshot():
            cpu_percent = round(proc.cpu_percent(interval=None) or 0.0, 2)
            mem_percent = round(proc.memory_percent() or 0.0, 2)

            if process_name.startswith("pid-"):
                process_name = _normalize_process_name(pid, proc.name())

            if process_owner == PROCESS_STATUS_UNKNOWN:
                process_owner = _normalize_process_owner(proc.username())

            if process_status == PROCESS_STATUS_UNKNOWN:
                process_status = proc.status() or PROCESS_STATUS_UNKNOWN
    except psutil.ZombieProcess:
        cpu_percent = 0.0
        mem_percent = 0.0
        process_status = PROCESS_STATUS_ZOMBIE
    except psutil.AccessDenied:
        cpu_percent = 0.0
        mem_percent = 0.0
        if process_status == PROCESS_STATUS_UNKNOWN:
            process_status = PROCESS_STATUS_ACCESS_DENIED
        if process_owner == PROCESS_STATUS_UNKNOWN:
            process_owner = "restricted"
    except psutil.NoSuchProcess:
        return None

    return {
        "pid": pid,
        "name": process_name,
        "cpu": cpu_percent,
        "mem": mem_percent,
        "status": process_status,
        "owner": process_owner,
    }


def _sort_processes(processes: list[dict], sort_by: str, reverse: bool) -> list[dict]:
    if sort_by not in PROCESS_SORT_FIELDS:
        sort_by = "pid"

    if sort_by in {"name", "status", "owner"}:
        return sorted(
            processes,
            key=lambda process: (process[sort_by].casefold(), process["pid"]),
            reverse=reverse,
        )

    return sorted(
        processes,
        key=lambda process: (process[sort_by], process["pid"]),
        reverse=reverse,
    )


def get_processes(
    filter_name: Optional[str] = None,
    sort_by: str = "pid",
    sort_direction: str = "asc",
    skip: int = 0,
    limit: Optional[int] = None,
):
    processes = list(
        psutil.process_iter(
            ["pid", "name", "status", "username"],
            ad_value=None,
        )
    )
    _prime_process_cpu_counters(processes)

    normalized_filter = filter_name.strip().casefold() if filter_name else None
    collected_processes = []
    for proc in processes:
        process_info = _build_process_info(proc)
        if process_info is None:
            continue
        if normalized_filter and normalized_filter not in process_info["name"].casefold():
            continue
        collected_processes.append(process_info)

    reverse = sort_direction == "desc"
    sorted_processes = _sort_processes(collected_processes, sort_by, reverse)
    total = len(sorted_processes)

    effective_limit = limit if limit is not None else settings.processes_default_limit
    effective_limit = min(max(1, effective_limit), settings.processes_max_limit)
    paginated_processes = sorted_processes[skip:skip + effective_limit]

    return paginated_processes, total


def _safe_process_name(process: psutil.Process) -> str:
    try:
        return process.name()
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return str(process.pid)
    except psutil.AccessDenied:
        return f"pid-{process.pid}"


def _ensure_process_stopped(processes):
    gone, alive = psutil.wait_procs(
        processes,
        timeout=PROCESS_ACTION_TIMEOUT_SECONDS,
    )
    if alive:
        alive_pids = ", ".join(str(process.pid) for process in alive)
        raise HTTPException(
            status_code=409,
            detail=f"Processes did not stop in time: {alive_pids}",
        )
    return gone


def manage_process(pid: int, action: str, priority: int = None):
    try:
        target_process = psutil.Process(pid)
        process_name = _safe_process_name(target_process)

        if action == "kill":
            target_process.kill()
            _ensure_process_stopped([target_process])
            return {
                "status": "success",
                "message": f"Process {pid} killed",
                "pid": pid,
                "action": action,
                "process_name": process_name,
                "affected_pids": [pid],
            }

        if action == "kill_tree":
            child_processes = target_process.children(recursive=True)
            processes_to_kill = child_processes + [target_process]

            for child in reversed(child_processes):
                child.kill()
            target_process.kill()
            _ensure_process_stopped(processes_to_kill)
            affected_pids = [process.pid for process in processes_to_kill]
            return {
                "status": "success",
                "message": f"Process tree {pid} killed",
                "pid": pid,
                "action": action,
                "process_name": process_name,
                "affected_pids": affected_pids,
            }

        if action == "priority":
            if priority is None:
                raise ValueError("Priority value is required")
            if not -20 <= priority <= 19:
                raise ValueError("Priority must be between -20 and 19")

            previous_priority = int(target_process.nice())
            target_process.nice(priority)
            current_priority = int(target_process.nice())
            return {
                "status": "success",
                "message": f"Priority for process {pid} set to {current_priority}",
                "pid": pid,
                "action": action,
                "process_name": process_name,
                "affected_pids": [pid],
                "previous_priority": previous_priority,
                "current_priority": current_priority,
            }

        raise ValueError(f"Unsupported action: {action}")
    except psutil.NoSuchProcess as exc:
        raise HTTPException(status_code=404, detail=f"Process {pid} not found") from exc
    except psutil.AccessDenied as exc:
        raise HTTPException(status_code=403, detail=f"Access denied for process {pid}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e

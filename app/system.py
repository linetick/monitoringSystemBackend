from datetime import datetime, timezone
import socket

import psutil
from fastapi import HTTPException

from .config import settings


STATUS_OK = "ok"
STATUS_WARNING = "warning"
STATUS_CRITICAL = "critical"
PROCESS_ACTION_TIMEOUT_SECONDS = 3


def _resolve_hostname() -> str:
    if settings.server_name:
        return settings.server_name

    hostname_path = settings.metrics_hostname_path
    if hostname_path:
        try:
            with open(hostname_path, "r", encoding="utf-8") as file:
                hostname = file.read().strip()
                if hostname:
                    return hostname
        except OSError:
            pass

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


def get_processes(filter_name: str = None, sort_by: str = "pid", reverse: bool = False):
    procs = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'username']):
        try:
            info = proc.info
            # Фильтрация
            process_name = info["name"] or ""
            if filter_name and filter_name.lower() not in process_name.lower():
                continue
            
            procs.append({
                "pid": info['pid'],
                "name": process_name,
                "cpu": info['cpu_percent'] or 0.0,
                "mem": info['memory_percent'] or 0.0,
                "status": info['status'],
                "owner": info['username'] or "root"
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Сортировка
    if sort_by in ["pid", "name", "cpu", "mem", "status", "owner"]:
        procs.sort(key=lambda x: x[sort_by], reverse=reverse)
    
    return procs


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

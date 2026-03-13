import os
import time

import psutil
from fastapi import HTTPException


def get_server_metrics():
    # Загрузка CPU (интервал 1 сек для точности)
    cpu_percent = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # Алерты (простая логика)
    alerts = []
    if cpu_percent > 90: alerts.append("High CPU Load")
    if mem.percent > 90: alerts.append("High Memory Usage")
    if disk.percent > 90: alerts.append("Disk Space Low")

    return {
        "hostname": os.uname().nodename,
        "cpu_percent": cpu_percent,
        "mem_percent": mem.percent,
        "disk_percent": disk.percent,
        "last_update": time.time(),
        "status": "critical" if alerts else "ok",
        "alerts": alerts
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

def manage_process(pid: int, action: str, priority: int = None):
    try:
        p = psutil.Process(pid)
        if action == "kill":
            p.kill()
            return f"Process {pid} killed"
        elif action == "kill_tree":
            for child in p.children(recursive=True):
                child.kill()
            p.kill()
            return f"Process tree {pid} killed"
        elif action == "priority":
            if priority is None:
                raise ValueError("Priority value is required")
            if not -20 <= priority <= 19:
                raise ValueError("Priority must be between -20 and 19")
            p.nice(priority)
            return f"Priority for process {pid} set to {priority}"
        raise ValueError(f"Unsupported action: {action}")
    except psutil.NoSuchProcess as exc:
        raise HTTPException(status_code=404, detail=f"Process {pid} not found") from exc
    except psutil.AccessDenied as exc:
        raise HTTPException(status_code=403, detail=f"Access denied for process {pid}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e

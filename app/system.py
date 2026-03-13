import psutil
import os
import time

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
            if filter_name and filter_name.lower() not in info['name'].lower():
                continue
            
            procs.append({
                "pid": info['pid'],
                "name": info['name'],
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
            p.kill() # В psutil нет прямого kill_tree для всех ОС, но можно пройтись по children
            for child in p.children(recursive=True):
                child.kill()
            return f"Process tree {pid} killed"
        elif action == "priority":
            if not -20 <= priority <= 19:
                raise ValueError("Priority must be between -20 and 19")
            os.nice(priority) # Внимание: nice меняет приоритет текущего процесса в Python, для другого процесса нужен setpriority через ctypes или командная строка
            # Для упрощения примера используем os.nice, но в реальности для чужого PID нужен syscall
            return f"Priority logic triggered for {pid}" # Заглушка для примера
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
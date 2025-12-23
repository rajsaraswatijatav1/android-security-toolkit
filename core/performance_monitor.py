#!/usr/bin/env python3
"""
ANDROID SECURITY TOOLKIT v2.0 - LEGAL NOTICE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AUTHORIZED USE ONLY. PROHIBITED: Unauthorized access, spying, data theft.
REQUIRES: Device ownership OR written permission. VIOLATION: 5 years imprisonment.
--consent flag mandatory. All actions logged to loot/audit.log.
BY USING THIS TOOL, YOU ACCEPT FULL LEGAL RESPONSIBILITY.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import time
import psutil
import logging
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
import json
import os


@dataclass
class PerformanceMetric:
    """Represents a performance measurement."""
    
    timestamp: float
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    disk_io_read_mb: float
    disk_io_write_mb: float
    network_bytes_sent: int
    network_bytes_recv: int
    threads_count: int
    processes_count: int
    custom_metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskMetric:
    """Represents metrics for a specific task."""
    
    task_name: str
    start_time: float
    end_time: Optional[float] = None
    duration: Optional[float] = None
    items_processed: int = 0
    throughput_items_per_sec: Optional[float] = None
    memory_peak_mb: Optional[float] = None
    status: str = "running"
    error: Optional[str] = None


class PerformanceMonitor:
    """
    Comprehensive performance monitoring for Android security toolkit.
    
    Monitors:
    - CPU usage
    - Memory usage
    - Disk I/O
    - Network activity
    - Thread/process counts
    - Custom application metrics
    - Task execution times
    """
    
    def __init__(self, monitoring_interval: float = 1.0):
        """
        Initialize performance monitor.
        
        Args:
            monitoring_interval: Seconds between system metrics collection
        """
        self.monitoring_interval = monitoring_interval
        self.logger = logging.getLogger("AST.PerformanceMonitor")
        
        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread = None
        self.metrics_lock = threading.Lock()
        
        # Metrics storage
        self.system_metrics: List[PerformanceMetric] = []
        self.task_metrics: List[TaskMetric] = []
        
        # Baseline metrics for comparison
        self.baseline_metrics: Optional[PerformanceMetric] = None
        
        # Callbacks for alerts
        self.alert_callbacks: List[Callable] = []
        
        # Thresholds for alerts
        self.cpu_threshold = 90.0  # 90% CPU usage
        self.memory_threshold = 85.0  # 85% memory usage
        self.disk_io_threshold = 100.0  # 100 MB/s
        
        # Performance counters
        self.counters: Dict[str, int] = {}
        self.counter_lock = threading.Lock()
    
    def start_monitoring(self) -> None:
        """Start system performance monitoring."""
        if self.is_monitoring:
            self.logger.warning("Monitoring already active")
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        # Capture baseline metrics
        time.sleep(2)  # Wait for initial readings
        self.capture_baseline()
        
        self.logger.info("Performance monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop system performance monitoring."""
        self.is_monitoring = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        self.logger.info("Performance monitoring stopped")
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop running in separate thread."""
        while self.is_monitoring:
            try:
                # Collect system metrics
                metric = self._collect_system_metrics()
                
                with self.metrics_lock:
                    self.system_metrics.append(metric)
                    
                    # Keep only last 1000 metrics to prevent memory bloat
                    if len(self.system_metrics) > 1000:
                        self.system_metrics = self.system_metrics[-1000:]
                
                # Check for threshold breaches
                self._check_alerts(metric)
                
                time.sleep(self.monitoring_interval)
                
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                time.sleep(self.monitoring_interval)
    
    def _collect_system_metrics(self) -> PerformanceMetric:
        """Collect current system metrics."""
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Memory metrics
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_used_mb = memory.used / (1024 * 1024)  # Convert to MB
        
        # Disk I/O metrics
        disk_io = psutil.disk_io_counters()
        disk_io_read_mb = disk_io.read_bytes / (1024 * 1024) if disk_io else 0
        disk_io_write_mb = disk_io.write_bytes / (1024 * 1024) if disk_io else 0
        
        # Network metrics
        network = psutil.net_io_counters()
        network_bytes_sent = network.bytes_sent if network else 0
        network_bytes_recv = network.bytes_recv if network else 0
        
        # Process metrics
        threads_count = threading.active_count()
        processes_count = len(psutil.pids())
        
        return PerformanceMetric(
            timestamp=time.time(),
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            memory_used_mb=memory_used_mb,
            disk_io_read_mb=disk_io_read_mb,
            disk_io_write_mb=disk_io_write_mb,
            network_bytes_sent=network_bytes_sent,
            network_bytes_recv=network_bytes_recv,
            threads_count=threads_count,
            processes_count=processes_count
        )
    
    def capture_baseline(self) -> None:
        """Capture baseline system metrics."""
        # Wait a bit for stable readings
        time.sleep(2)
        
        with self.metrics_lock:
            if len(self.system_metrics) >= 3:
                # Use average of last 3 readings as baseline
                recent = self.system_metrics[-3:]
                self.baseline_metrics = PerformanceMetric(
                    timestamp=time.time(),
                    cpu_percent=sum(m.cpu_percent for m in recent) / 3,
                    memory_percent=sum(m.memory_percent for m in recent) / 3,
                    memory_used_mb=sum(m.memory_used_mb for m in recent) / 3,
                    disk_io_read_mb=sum(m.disk_io_read_mb for m in recent) / 3,
                    disk_io_write_mb=sum(m.disk_io_write_mb for m in recent) / 3,
                    network_bytes_sent=recent[-1].network_bytes_sent,
                    network_bytes_recv=recent[-1].network_bytes_recv,
                    threads_count=sum(m.threads_count for m in recent) / 3,
                    processes_count=sum(m.processes_count for m in recent) / 3
                )
                
                self.logger.info("Baseline metrics captured")
    
    def start_task(self, task_name: str) -> TaskMetric:
        """
        Start tracking a task.
        
        Args:
            task_name: Name of the task
            
        Returns:
            TaskMetric instance
        """
        task = TaskMetric(
            task_name=task_name,
            start_time=time.time()
        )
        
        with self.metrics_lock:
            self.task_metrics.append(task)
        
        self.logger.debug(f"Task started: {task_name}")
        return task
    
    def end_task(self, task: TaskMetric, items_processed: int = 0, 
                error: Optional[str] = None) -> None:
        """
        End task tracking.
        
        Args:
            task: TaskMetric instance
            items_processed: Number of items processed
            error: Error message if task failed
        """
        task.end_time = time.time()
        task.duration = task.end_time - task.start_time
        task.items_processed = items_processed
        task.error = error
        task.status = "failed" if error else "completed"
        
        # Calculate throughput
        if task.duration and task.duration > 0:
            task.throughput_items_per_sec = items_processed / task.duration
        
        # Capture peak memory
        task.memory_peak_mb = psutil.virtual_memory().used / (1024 * 1024)
        
        self.logger.debug(
            f"Task completed: {task.task_name} - "
            f"Duration: {task.duration:.2f}s, "
            f"Throughput: {task.throughput_items_per_sec:.2f} items/sec"
        )
    
    def task_context(self, task_name: str):
        """
        Context manager for task monitoring.
        
        Usage:
            with monitor.task_context("my_task") as task:
                # Do work
                task.items_processed = 100
        """
        return TaskContext(self, task_name)
    
    def _check_alerts(self, metric: PerformanceMetric) -> None:
        """Check if metrics exceed thresholds and trigger alerts."""
        alerts = []
        
        # CPU threshold
        if metric.cpu_percent > self.cpu_threshold:
            alerts.append(f"High CPU usage: {metric.cpu_percent:.1f}%")
        
        # Memory threshold
        if metric.memory_percent > self.memory_threshold:
            alerts.append(f"High memory usage: {metric.memory_percent:.1f}%")
        
        # Disk I/O threshold (calculate rate)
        if len(self.system_metrics) > 1:
            prev_metric = self.system_metrics[-2]
            time_diff = metric.timestamp - prev_metric.timestamp
            if time_diff > 0:
                read_rate = (metric.disk_io_read_mb - prev_metric.disk_io_read_mb) / time_diff
                write_rate = (metric.disk_io_write_mb - prev_metric.disk_io_write_mb) / time_diff
                
                if read_rate > self.disk_io_threshold:
                    alerts.append(f"High disk read rate: {read_rate:.1f} MB/s")
                
                if write_rate > self.disk_io_threshold:
                    alerts.append(f"High disk write rate: {write_rate:.1f} MB/s")
        
        # Trigger alert callbacks
        for alert in alerts:
            self.logger.warning(alert)
            for callback in self.alert_callbacks:
                try:
                    callback(alert, metric)
                except Exception as e:
                    self.logger.error(f"Alert callback error: {e}")
    
    def add_alert_callback(self, callback: Callable[[str, PerformanceMetric], None]) -> None:
        """Add callback for performance alerts."""
        self.alert_callbacks.append(callback)
    
    def increment_counter(self, counter_name: str, value: int = 1) -> None:
        """Increment a performance counter."""
        with self.counter_lock:
            self.counters[counter_name] = self.counters.get(counter_name, 0) + value
    
    def get_counter(self, counter_name: str) -> int:
        """Get current counter value."""
        with self.counter_lock:
            return self.counters.get(counter_name, 0)
    
    def get_counters(self) -> Dict[str, int]:
        """Get all counters."""
        with self.counter_lock:
            return self.counters.copy()
    
    def get_current_metrics(self) -> PerformanceMetric:
        """Get current system metrics."""
        return self._collect_system_metrics()
    
    def get_metrics_summary(self, duration: Optional[float] = None) -> Dict[str, Any]:
        """
        Get performance metrics summary.
        
        Args:
            duration: Time window in seconds (None for all metrics)
            
        Returns:
            Dictionary with metrics summary
        """
        with self.metrics_lock:
            # Filter metrics by duration
            if duration and self.system_metrics:
                cutoff_time = time.time() - duration
                metrics = [m for m in self.system_metrics if m.timestamp >= cutoff_time]
            else:
                metrics = self.system_metrics.copy()
            
            if not metrics:
                return {"error": "No metrics available"}
            
            # Calculate statistics
            cpu_values = [m.cpu_percent for m in metrics]
            memory_values = [m.memory_percent for m in metrics]
            memory_mb_values = [m.memory_used_mb for m in metrics]
            
            summary = {
                "period_seconds": duration or (metrics[-1].timestamp - metrics[0].timestamp),
                "sample_count": len(metrics),
                "cpu": {
                    "average": sum(cpu_values) / len(cpu_values),
                    "min": min(cpu_values),
                    "max": max(cpu_values),
                    "current": cpu_values[-1]
                },
                "memory": {
                    "average_percent": sum(memory_values) / len(memory_values),
                    "min_percent": min(memory_values),
                    "max_percent": max(memory_values),
                    "current_percent": memory_values[-1],
                    "average_mb": sum(memory_mb_values) / len(memory_mb_values),
                    "current_mb": memory_mb_values[-1]
                },
                "counters": self.get_counters(),
                "tasks": {
                    "total": len(self.task_metrics),
                    "completed": sum(1 for t in self.task_metrics if t.status == "completed"),
                    "failed": sum(1 for t in self.task_metrics if t.status == "failed"),
                    "running": sum(1 for t in self.task_metrics if t.status == "running")
                }
            }
            
            # Add task throughput statistics
            completed_tasks = [t for t in self.task_metrics if t.status == "completed" and t.throughput_items_per_sec]
            if completed_tasks:
                throughputs = [t.throughput_items_per_sec for t in completed_tasks]
                summary["tasks"]["average_throughput"] = sum(throughputs) / len(throughputs)
                summary["tasks"]["max_throughput"] = max(throughputs)
                summary["tasks"]["min_throughput"] = min(throughputs)
            
            return summary
    
    def export_metrics(self, filename: str, format_type: str = "json") -> None:
        """
        Export metrics to file.
        
        Args:
            filename: Output filename
            format_type: Export format (json, csv)
        """
        summary = self.get_metrics_summary()
        
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        
        if format_type.lower() == "json":
            with open(filename, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
        
        elif format_type.lower() == "csv":
            import csv
            
            # Export system metrics
            csv_file = filename.replace('.json', '_system.csv')
            with open(csv_file, 'w', newline='') as f:
                if self.system_metrics:
                    writer = csv.DictWriter(f, fieldnames=self.system_metrics[0].__dict__.keys())
                    writer.writeheader()
                    for metric in self.system_metrics:
                        writer.writerow(metric.__dict__)
            
            # Export task metrics
            csv_file = filename.replace('.json', '_tasks.csv')
            with open(csv_file, 'w', newline='') as f:
                if self.task_metrics:
                    writer = csv.DictWriter(f, fieldnames=self.task_metrics[0].__dict__.keys())
                    writer.writeheader()
                    for metric in self.task_metrics:
                        writer.writerow(metric.__dict__)
        
        self.logger.info(f"Metrics exported to {filename}")
    
    def reset_metrics(self) -> None:
        """Reset all metrics."""
        with self.metrics_lock:
            self.system_metrics.clear()
            self.task_metrics.clear()
            self.baseline_metrics = None
        
        with self.counter_lock:
            self.counters.clear()
        
        self.logger.info("Metrics reset")


class TaskContext:
    """Context manager for task monitoring."""
    
    def __init__(self, monitor: PerformanceMonitor, task_name: str):
        self.monitor = monitor
        self.task_name = task_name
        self.task = None
    
    def __enter__(self):
        self.task = self.monitor.start_task(self.task_name)
        return self.task
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        error = str(exc_val) if exc_val else None
        self.monitor.end_task(self.task, error=error)
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

import asyncio
import logging
import json
import time
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from celery import Celery
import redis
import sqlite3

from modules.adb_security_scanner import ADBSecurityScanner
from modules.adb_data_extractor import ADBDataExtractor
from modules.apk_analyzer import APKAnalyzer
from modules.android_password_cracker import AndroidPasswordCracker
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.device_monitor import DeviceMonitor


# Pydantic Models
class DeviceRequest(BaseModel):
    device_id: str = Field(..., description="Target device ID")
    consent: bool = Field(..., description="Legal consent confirmation")


class ScanRequest(BaseModel):
    device_id: Optional[str] = Field(None, description="Target device ID")
    scan_type: str = Field("full", description="Type of scan to perform")
    tcp_scan: bool = Field(False, description="Enable TCP/IP scanning")
    consent: bool = Field(..., description="Legal consent confirmation")


class CrackRequest(BaseModel):
    device_id: Optional[str] = Field(None, description="Target device ID")
    attack_type: str = Field(..., description="Attack type: pin, pattern, password")
    min_length: int = Field(4, description="Minimum length for PINs")
    max_length: int = Field(8, description="Maximum length for PINs")
    wordlist: Optional[str] = Field(None, description="Wordlist file path")
    threads: int = Field(8, description="Number of threads")
    consent: bool = Field(..., description="Legal consent confirmation")


class APKAnalysisRequest(BaseModel):
    apk_path: str = Field(..., description="Path to APK file")
    deep_analysis: bool = Field(False, description="Enable deep analysis")
    consent: bool = Field(..., description="Legal consent confirmation")


class MonitorRequest(BaseModel):
    device_id: Optional[str] = Field(None, description="Device to monitor")
    duration: int = Field(60, description="Monitoring duration in seconds")
    webhook_url: Optional[str] = Field(None, description="Webhook for alerts")
    consent: bool = Field(..., description="Legal consent confirmation")


class TaskStatus(BaseModel):
    task_id: str
    status: str
    progress: float = 0.0
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: str
    updated_at: str


class ScanResult(BaseModel):
    scan_id: str
    device_id: Optional[str]
    findings: List[Dict[str, Any]]
    metrics: Dict[str, Any]
    risk_score: float
    completed_at: str


# API Server Class
class APIServer:
    def __init__(self):
        self.app = FastAPI(
            title="Android Security Toolkit API",
            description="RESTful API for Android security testing",
            version="2.0.0"
        )
        
        # Setup middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Security
        self.security = HTTPBearer()
        
        # Redis for task queue
        self.redis_client = redis.Redis(host='localhost', port=6379, db=0)
        
        # Celery for background tasks
        self.celery_app = Celery(
            'ast_tasks',
            broker='redis://localhost:6379',
            backend='redis://localhost:6379'
        )
        
        # Task tracking
        self.tasks = {}
        self.websocket_connections = []
        
        # Initialize database
        self._init_database()
        
        # Setup routes
        self._setup_routes()
    
    def _init_database(self) -> None:
        """Initialize SQLite database for task tracking."""
        db_path = Path("loot") / "api_tasks.db"
        db_path.parent.mkdir(exist_ok=True)
        
        self.db_conn = sqlite3.connect(db_path)
        self.db_conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                task_type TEXT,
                status TEXT,
                progress REAL,
                result TEXT,
                error TEXT,
                created_at TEXT,
                updated_at TEXT,
                device_id TEXT,
                user_id TEXT
            )
        """)
        
        self.db_conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                scan_id TEXT PRIMARY KEY,
                device_id TEXT,
                findings TEXT,
                metrics TEXT,
                risk_score REAL,
                completed_at TEXT
            )
        """)
    
    def _setup_routes(self) -> None:
        """Setup API routes."""
        
        @self.app.get("/")
        async def root():
            return {
                "name": "Android Security Toolkit API",
                "version": "2.0.0",
                "legal_notice": "AUTHORIZED USE ONLY - Requires device ownership or written permission",
                "endpoints": {
                    "scan": "/api/v1/scan",
                    "crack": "/api/v1/crack",
                    "analyze": "/api/v1/analyze",
                    "monitor": "/api/v1/monitor",
                    "tasks": "/api/v1/tasks/{task_id}",
                    "websocket": "/ws"
                }
            }
        
        @self.app.post("/api/v1/scan", response_model=TaskStatus)
        async def start_scan(request: ScanRequest):
            """Start ADB security scan."""
            if not request.consent:
                raise HTTPException(status_code=400, detail="Consent required for legal compliance")
            
            task_id = f"scan_{int(time.time())}"
            
            # Start background task
            task = self.celery_app.send_task(
                'tasks.perform_scan',
                args=[request.dict()],
                task_id=task_id
            )
            
            # Track task
            self.tasks[task_id] = {
                "task_type": "scan",
                "status": "pending",
                "created_at": datetime.now().isoformat(),
                "device_id": request.device_id
            }
            
            return TaskStatus(
                task_id=task_id,
                status="pending",
                created_at=self.tasks[task_id]["created_at"],
                updated_at=self.tasks[task_id]["created_at"]
            )
        
        @self.app.post("/api/v1/crack", response_model=TaskStatus)
        async def start_crack(request: CrackRequest):
            """Start password cracking attack."""
            if not request.consent:
                raise HTTPException(status_code=400, detail="Consent required for legal compliance")
            
            task_id = f"crack_{int(time.time())}"
            
            # Start background task
            task = self.celery_app.send_task(
                'tasks.perform_crack',
                args=[request.dict()],
                task_id=task_id
            )
            
            # Track task
            self.tasks[task_id] = {
                "task_type": "crack",
                "status": "pending",
                "created_at": datetime.now().isoformat(),
                "device_id": request.device_id
            }
            
            return TaskStatus(
                task_id=task_id,
                status="pending",
                created_at=self.tasks[task_id]["created_at"],
                updated_at=self.tasks[task_id]["created_at"]
            )
        
        @self.app.post("/api/v1/analyze", response_model=TaskStatus)
        async def start_analysis(request: APKAnalysisRequest):
            """Start APK analysis."""
            if not request.consent:
                raise HTTPException(status_code=400, detail="Consent required for legal compliance")
            
            if not Path(request.apk_path).exists():
                raise HTTPException(status_code=400, detail="APK file not found")
            
            task_id = f"analyze_{int(time.time())}"
            
            # Start background task
            task = self.celery_app.send_task(
                'tasks.perform_analysis',
                args=[request.dict()],
                task_id=task_id
            )
            
            # Track task
            self.tasks[task_id] = {
                "task_type": "analyze",
                "status": "pending",
                "created_at": datetime.now().isoformat(),
                "apk_path": request.apk_path
            }
            
            return TaskStatus(
                task_id=task_id,
                status="pending",
                created_at=self.tasks[task_id]["created_at"],
                updated_at=self.tasks[task_id]["created_at"]
            )
        
        @self.app.post("/api/v1/monitor", response_model=TaskStatus)
        async def start_monitoring(request: MonitorRequest):
            """Start device monitoring."""
            if not request.consent:
                raise HTTPException(status_code=400, detail="Consent required for legal compliance")
            
            task_id = f"monitor_{int(time.time())}"
            
            # Start background task
            task = self.celery_app.send_task(
                'tasks.perform_monitoring',
                args=[request.dict()],
                task_id=task_id
            )
            
            # Track task
            self.tasks[task_id] = {
                "task_type": "monitor",
                "status": "pending",
                "created_at": datetime.now().isoformat(),
                "device_id": request.device_id
            }
            
            return TaskStatus(
                task_id=task_id,
                status="pending",
                created_at=self.tasks[task_id]["created_at"],
                updated_at=self.tasks[task_id]["created_at"]
            )
        
        @self.app.get("/api/v1/tasks/{task_id}", response_model=TaskStatus)
        async def get_task_status(task_id: str):
            """Get task status and results."""
            if task_id not in self.tasks:
                raise HTTPException(status_code=404, detail="Task not found")
            
            task_info = self.tasks[task_id]
            
            # Get Celery task result
            celery_task = self.celery_app.AsyncResult(task_id)
            
            status = TaskStatus(
                task_id=task_id,
                status=celery_task.status,
                progress=task_info.get("progress", 0.0),
                created_at=task_info["created_at"],
                updated_at=datetime.now().isoformat()
            )
            
            if celery_task.ready():
                if celery_task.successful():
                    status.result = celery_task.result
                else:
                    status.error = str(celery_task.result)
            
            return status
        
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket endpoint for real-time updates."""
            await websocket.accept()
            self.websocket_connections.append(websocket)
            
            try:
                while True:
                    # Send periodic updates
                    update = {
                        "timestamp": datetime.now().isoformat(),
                        "active_tasks": len(self.tasks),
                        "connections": len(self.websocket_connections)
                    }
                    
                    await websocket.send_json(update)
                    await asyncio.sleep(5)
            
            except WebSocketDisconnect:
                self.websocket_connections.remove(websocket)
            except Exception as e:
                self.logger.error(f"WebSocket error: {e}")
                self.websocket_connections.remove(websocket)
        
        @self.app.get("/api/v1/health")
        async def health_check():
            """Health check endpoint."""
            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "version": "2.0.0",
                "tasks": len(self.tasks),
                "connections": len(self.websocket_connections)
            }
        
        @self.app.get("/api/v1/results")
        async def get_results(
            limit: int = 10,
            offset: int = 0,
            device_id: Optional[str] = None
        ):
            """Get scan results with pagination."""
            cursor = self.db_conn.cursor()
            
            query = "SELECT * FROM scan_results ORDER BY completed_at DESC LIMIT ? OFFSET ?"
            params = [limit, offset]
            
            if device_id:
                query = "SELECT * FROM scan_results WHERE device_id = ? ORDER BY completed_at DESC LIMIT ? OFFSET ?"
                params = [device_id, limit, offset]
            
            cursor.execute(query, params)
            results = cursor.fetchall()
            
            return {
                "results": [
                    {
                        "scan_id": row[0],
                        "device_id": row[1],
                        "findings": json.loads(row[2]),
                        "metrics": json.loads(row[3]),
                        "risk_score": row[4],
                        "completed_at": row[5]
                    }
                    for row in results
                ],
                "limit": limit,
                "offset": offset
            }


# Celery Tasks
@APIServer.celery_app.task
def perform_scan(scan_config: Dict[str, Any]) -> Dict[str, Any]:
    """Perform ADB security scan."""
    scanner = ADBSecurityScanner(device_id=scan_config.get('device_id'))
    results = scanner.scan()
    
    # Store results in database
    db_path = Path("loot") / "api_tasks.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """INSERT INTO scan_results VALUES (?, ?, ?, ?, ?, ?)""",
        (
            scan_config.get('task_id', f"scan_{int(time.time())}"),
            scan_config.get('device_id'),
            json.dumps(results.get('findings', [])),
            json.dumps(results.get('metrics', {})),
            results.get('risk_score', 0),
            datetime.now().isoformat()
        )
    )
    conn.commit()
    conn.close()
    
    return results


@APIServer.celery_app.task
def perform_crack(crack_config: Dict[str, Any]) -> Dict[str, Any]:
    """Perform password cracking attack."""
    cracker = AndroidPasswordCracker(
        device_id=crack_config.get('device_id'),
        threads=crack_config.get('threads', 8)
    )
    
    if crack_config['attack_type'] == 'pin':
        result = cracker.crack_device_pin(
            min_length=crack_config.get('min_length', 4),
            max_length=crack_config.get('max_length', 8)
        )
    elif crack_config['attack_type'] == 'pattern':
        result = cracker.crack_device_pattern()
    elif crack_config['attack_type'] == 'password':
        result = cracker.crack_device_password()
    
    return {
        "attack_type": crack_config['attack_type'],
        "result": result,
        "success": result is not None
    }


@APIServer.celery_app.task
def perform_analysis(analysis_config: Dict[str, Any]) -> Dict[str, Any]:
    """Perform APK analysis."""
    analyzer = APKAnalyzer()
    results = analyzer.analyze(analysis_config['apk_path'])
    
    return results


@APIServer.celery_app.task
def perform_monitoring(monitor_config: Dict[str, Any]) -> Dict[str, Any]:
    """Perform device monitoring."""
    monitor = DeviceMonitor(
        device_id=monitor_config.get('device_id'),
        webhook_url=monitor_config.get('webhook_url')
    )
    
    monitor.start_monitoring()
    time.sleep(monitor_config.get('duration', 60))
    monitor.stop_monitoring()
    
    return {
        "monitoring_duration": monitor_config.get('duration', 60),
        "activity_log_entries": len(monitor.activity_log)
    }


# Main function
def main():
    import uvicorn
    
    server = APIServer()
    
    uvicorn.run(
        server.app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )


if __name__ == "__main__":
    main()
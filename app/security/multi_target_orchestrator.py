"""
Multi-Target Orchestrator
Manages multiple targets simultaneously with distributed scanning and load balancing
"""

import asyncio
import logging
import json
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
import aiohttp
from urllib.parse import urlparse

from app.core.config import settings
from app.security.ai_agent import AutonomousPentestAgent
from app.security.threat_intelligence import ThreatIntelligenceService
from app.security.advanced_reporting import AdvancedReportingService
from app.security.burp_client import BurpClient

logger = logging.getLogger(__name__)

class TargetStatus(Enum):
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"

class OrchestrationMode(Enum):
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    DISTRIBUTED = "distributed"
    ADAPTIVE = "adaptive"

@dataclass
class TargetConfig:
    url: str
    priority: int = 1
    max_duration: int = 3600
    safety_level: str = "medium"
    scan_types: List[str] = field(default_factory=lambda: ["vulnerability", "threat_intelligence"])
    custom_headers: Dict[str, str] = field(default_factory=dict)
    authentication: Optional[Dict[str, Any]] = None
    scope: List[str] = field(default_factory=list)  # URLs to include/exclude

@dataclass
class TargetStatus:
    target_id: str
    url: str
    status: TargetStatus
    progress: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error_message: Optional[str] = None
    vulnerabilities_found: int = 0
    risk_score: float = 0.0
    current_phase: str = "initialization"

@dataclass
class OrchestrationSession:
    session_id: str
    mode: OrchestrationMode
    targets: List[TargetConfig]
    status: Dict[str, TargetStatus]
    start_time: datetime
    end_time: Optional[datetime] = None
    total_targets: int = 0
    completed_targets: int = 0
    failed_targets: int = 0
    overall_progress: float = 0.0
    resource_usage: Dict[str, float] = field(default_factory=dict)

class LoadBalancer:
    """Intelligent load balancer for distributed scanning"""
    
    def __init__(self, max_concurrent_scans: int = 5):
        self.max_concurrent_scans = max_concurrent_scans
        self.active_scans: Set[str] = set()
        self.scan_queue: List[Tuple[str, TargetConfig]] = []
        self.scan_history: Dict[str, Dict[str, Any]] = {}
        self.resource_usage: Dict[str, float] = {
            'cpu': 0.0,
            'memory': 0.0,
            'network': 0.0
        }
    
    async def add_target(self, target_id: str, target_config: TargetConfig) -> bool:
        """Add target to scan queue"""
        try:
            self.scan_queue.append((target_id, target_config))
            logger.info(f"Added target {target_id} to scan queue")
            return True
        except Exception as e:
            logger.error(f"Error adding target to queue: {e}")
            return False
    
    async def get_next_target(self) -> Optional[Tuple[str, TargetConfig]]:
        """Get next target for scanning based on priority and resources"""
        try:
            if not self.scan_queue:
                return None
            
            # Check if we can start a new scan
            if len(self.active_scans) >= self.max_concurrent_scans:
                return None
            
            # Sort queue by priority and estimated resource usage
            self.scan_queue.sort(key=lambda x: (
                -x[1].priority,  # Higher priority first
                self._estimate_resource_usage(x[1])  # Lower resource usage first
            ))
            
            target_id, target_config = self.scan_queue.pop(0)
            self.active_scans.add(target_id)
            
            logger.info(f"Starting scan for target {target_id}")
            return target_id, target_config
            
        except Exception as e:
            logger.error(f"Error getting next target: {e}")
            return None
    
    def complete_scan(self, target_id: str, scan_result: Dict[str, Any]):
        """Mark scan as completed and update history"""
        try:
            if target_id in self.active_scans:
                self.active_scans.remove(target_id)
            
            self.scan_history[target_id] = {
                'completion_time': datetime.now(),
                'result': scan_result,
                'resource_usage': self.resource_usage.copy()
            }
            
            logger.info(f"Completed scan for target {target_id}")
            
        except Exception as e:
            logger.error(f"Error completing scan: {e}")
    
    def fail_scan(self, target_id: str, error_message: str):
        """Mark scan as failed"""
        try:
            if target_id in self.active_scans:
                self.active_scans.remove(target_id)
            
            self.scan_history[target_id] = {
                'completion_time': datetime.now(),
                'error': error_message,
                'status': 'failed'
            }
            
            logger.error(f"Failed scan for target {target_id}: {error_message}")
            
        except Exception as e:
            logger.error(f"Error failing scan: {e}")
    
    def _estimate_resource_usage(self, target_config: TargetConfig) -> float:
        """Estimate resource usage for target"""
        base_usage = 1.0
        
        # Adjust based on scan types
        if "threat_intelligence" in target_config.scan_types:
            base_usage += 0.3
        
        if "ai_agent" in target_config.scan_types:
            base_usage += 0.5
        
        # Adjust based on scope size
        if target_config.scope:
            base_usage += len(target_config.scope) * 0.1
        
        return base_usage
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get current queue status"""
        return {
            'queue_length': len(self.scan_queue),
            'active_scans': len(self.active_scans),
            'max_concurrent': self.max_concurrent_scans,
            'resource_usage': self.resource_usage.copy(),
            'completed_scans': len(self.scan_history)
        }

class TargetManager:
    """Manages individual target scanning and status tracking"""
    
    def __init__(self):
        self.ai_agent = AutonomousPentestAgent()
        self.threat_intelligence = ThreatIntelligenceService()
        self.advanced_reporting = AdvancedReportingService()
        self.burp_client = BurpClient()
        self.target_statuses: Dict[str, TargetStatus] = {}
    
    async def scan_target(self, target_id: str, target_config: TargetConfig) -> Dict[str, Any]:
        """Scan a single target with all configured scan types"""
        try:
            # Update status
            self.target_statuses[target_id] = TargetStatus(
                target_id=target_id,
                url=target_config.url,
                status=TargetStatus.SCANNING,
                start_time=datetime.now(),
                current_phase="initialization"
            )
            
            scan_results = {
                'target_id': target_id,
                'url': target_config.url,
                'scan_start': datetime.now(),
                'vulnerabilities': [],
                'threat_intelligence': None,
                'ai_analysis': None,
                'risk_score': 0.0,
                'recommendations': []
            }
            
            # Phase 1: Basic vulnerability scanning
            self.target_statuses[target_id].current_phase = "vulnerability_scanning"
            self.target_statuses[target_id].progress = 0.2
            
            if "vulnerability" in target_config.scan_types:
                vulnerabilities = await self._run_vulnerability_scan(target_config)
                scan_results['vulnerabilities'] = vulnerabilities
                scan_results['risk_score'] = self._calculate_risk_score(vulnerabilities)
            
            # Phase 2: Threat intelligence
            self.target_statuses[target_id].current_phase = "threat_intelligence"
            self.target_statuses[target_id].progress = 0.5
            
            if "threat_intelligence" in target_config.scan_types:
                threat_report = await self.threat_intelligence.analyze_target(target_config.url)
                scan_results['threat_intelligence'] = threat_report
            
            # Phase 3: AI agent analysis
            self.target_statuses[target_id].current_phase = "ai_analysis"
            self.target_statuses[target_id].progress = 0.8
            
            if "ai_agent" in target_config.scan_types:
                ai_session_id = await self.ai_agent.start_autonomous_pentest(
                    target_config.url,
                    target_config.max_duration,
                    target_config.safety_level
                )
                scan_results['ai_analysis'] = {
                    'session_id': ai_session_id,
                    'status': 'running'
                }
            
            # Phase 4: Advanced reporting
            self.target_statuses[target_id].current_phase = "reporting"
            self.target_statuses[target_id].progress = 0.9
            
            if scan_results['vulnerabilities']:
                dashboard = await self.advanced_reporting.generate_executive_dashboard(
                    scan_results['vulnerabilities'],
                    target_config.url
                )
                scan_results['executive_dashboard'] = dashboard
            
            # Complete scan
            self.target_statuses[target_id].status = TargetStatus.COMPLETED
            self.target_statuses[target_id].progress = 1.0
            self.target_statuses[target_id].end_time = datetime.now()
            self.target_statuses[target_id].vulnerabilities_found = len(scan_results['vulnerabilities'])
            self.target_statuses[target_id].risk_score = scan_results['risk_score']
            
            scan_results['scan_end'] = datetime.now()
            scan_results['duration'] = (scan_results['scan_end'] - scan_results['scan_start']).total_seconds()
            
            logger.info(f"Completed scan for target {target_id}")
            return scan_results
            
        except Exception as e:
            logger.error(f"Error scanning target {target_id}: {e}")
            self.target_statuses[target_id].status = TargetStatus.FAILED
            self.target_statuses[target_id].error_message = str(e)
            self.target_statuses[target_id].end_time = datetime.now()
            return {
                'target_id': target_id,
                'url': target_config.url,
                'error': str(e),
                'status': 'failed'
            }
    
    async def _run_vulnerability_scan(self, target_config: TargetConfig) -> List[Dict]:
        """Run vulnerability scanning on target"""
        try:
            vulnerabilities = []
            
            # Burp Suite Pro scanning
            if self.burp_client:
                scan_result = await self.burp_client.start_scan(target_config.url)
                if scan_result:
                    burp_vulnerabilities = await self.burp_client.get_alerts()
                    vulnerabilities.extend(burp_vulnerabilities)
            
            # Custom scanning based on target configuration
            if target_config.custom_headers:
                # Add custom header scanning logic
                pass
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error in vulnerability scanning: {e}")
            return []
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate risk score for vulnerabilities"""
        if not vulnerabilities:
            return 0.0
        
        total_score = 0.0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity == 'critical':
                total_score += 1.0
            elif severity == 'high':
                total_score += 0.7
            elif severity == 'medium':
                total_score += 0.4
            elif severity == 'low':
                total_score += 0.1
        
        return min(total_score / len(vulnerabilities), 1.0)
    
    def get_target_status(self, target_id: str) -> Optional[TargetStatus]:
        """Get status of specific target"""
        return self.target_statuses.get(target_id)
    
    def get_all_target_statuses(self) -> Dict[str, TargetStatus]:
        """Get status of all targets"""
        return self.target_statuses.copy()

class MultiTargetOrchestrator:
    """Main orchestrator for managing multiple targets"""
    
    def __init__(self, max_concurrent_scans: int = 5):
        self.load_balancer = LoadBalancer(max_concurrent_scans)
        self.target_manager = TargetManager()
        self.active_sessions: Dict[str, OrchestrationSession] = {}
        self.session_history: Dict[str, OrchestrationSession] = {}
        self.is_running = False
        self.worker_tasks: List[asyncio.Task] = []
        
        logger.info("Multi-Target Orchestrator initialized")
    
    async def start_orchestration_session(self, targets: List[TargetConfig], 
                                        mode: OrchestrationMode = OrchestrationMode.PARALLEL) -> str:
        """Start a new orchestration session"""
        try:
            session_id = f"orchestration_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000, 9999)}"
            
            # Create session
            session = OrchestrationSession(
                session_id=session_id,
                mode=mode,
                targets=targets,
                status={},
                start_time=datetime.now(),
                total_targets=len(targets)
            )
            
            self.active_sessions[session_id] = session
            
            # Add targets to load balancer
            for i, target_config in enumerate(targets):
                target_id = f"{session_id}_target_{i}"
                await self.load_balancer.add_target(target_id, target_config)
                
                # Initialize status
                session.status[target_id] = TargetStatus(
                    target_id=target_id,
                    url=target_config.url,
                    status=TargetStatus.PENDING
                )
            
            # Start orchestration based on mode
            if mode == OrchestrationMode.PARALLEL:
                asyncio.create_task(self._run_parallel_orchestration(session_id))
            elif mode == OrchestrationMode.SEQUENTIAL:
                asyncio.create_task(self._run_sequential_orchestration(session_id))
            elif mode == OrchestrationMode.DISTRIBUTED:
                asyncio.create_task(self._run_distributed_orchestration(session_id))
            elif mode == OrchestrationMode.ADAPTIVE:
                asyncio.create_task(self._run_adaptive_orchestration(session_id))
            
            logger.info(f"Started orchestration session {session_id} with {len(targets)} targets")
            return session_id
            
        except Exception as e:
            logger.error(f"Error starting orchestration session: {e}")
            return None
    
    async def _run_parallel_orchestration(self, session_id: str):
        """Run parallel orchestration"""
        try:
            session = self.active_sessions[session_id]
            self.is_running = True
            
            # Start multiple worker tasks
            worker_count = min(len(session.targets), self.load_balancer.max_concurrent_scans)
            self.worker_tasks = [
                asyncio.create_task(self._worker_task(session_id))
                for _ in range(worker_count)
            ]
            
            # Wait for all workers to complete
            await asyncio.gather(*self.worker_tasks)
            
            # Finalize session
            await self._finalize_session(session_id)
            
        except Exception as e:
            logger.error(f"Error in parallel orchestration: {e}")
            await self._finalize_session(session_id, error=str(e))
    
    async def _run_sequential_orchestration(self, session_id: str):
        """Run sequential orchestration"""
        try:
            session = self.active_sessions[session_id]
            self.is_running = True
            
            # Process targets one by one
            for target_id in list(session.status.keys()):
                if not self.is_running:
                    break
                
                target_config = next(t for t in session.targets if f"target_{session.targets.index(t)}" in target_id)
                await self._process_target(session_id, target_id, target_config)
            
            await self._finalize_session(session_id)
            
        except Exception as e:
            logger.error(f"Error in sequential orchestration: {e}")
            await self._finalize_session(session_id, error=str(e))
    
    async def _run_distributed_orchestration(self, session_id: str):
        """Run distributed orchestration"""
        try:
            session = self.active_sessions[session_id]
            self.is_running = True
            
            # Similar to parallel but with resource monitoring
            worker_count = min(len(session.targets), self.load_balancer.max_concurrent_scans)
            self.worker_tasks = [
                asyncio.create_task(self._distributed_worker_task(session_id))
                for _ in range(worker_count)
            ]
            
            await asyncio.gather(*self.worker_tasks)
            await self._finalize_session(session_id)
            
        except Exception as e:
            logger.error(f"Error in distributed orchestration: {e}")
            await self._finalize_session(session_id, error=str(e))
    
    async def _run_adaptive_orchestration(self, session_id: str):
        """Run adaptive orchestration that adjusts based on performance"""
        try:
            session = self.active_sessions[session_id]
            self.is_running = True
            
            # Start with parallel mode
            await self._run_parallel_orchestration(session_id)
            
            # Analyze performance and adjust if needed
            performance_metrics = self._analyze_performance(session_id)
            if performance_metrics['avg_duration'] > 300:  # If average scan takes > 5 minutes
                logger.info("Adapting to sequential mode due to performance")
                # Could restart with different mode
            
        except Exception as e:
            logger.error(f"Error in adaptive orchestration: {e}")
            await self._finalize_session(session_id, error=str(e))
    
    async def _worker_task(self, session_id: str):
        """Worker task for processing targets"""
        try:
            while self.is_running:
                # Get next target from load balancer
                target_data = await self.load_balancer.get_next_target()
                if not target_data:
                    await asyncio.sleep(1)
                    continue
                
                target_id, target_config = target_data
                
                # Process target
                await self._process_target(session_id, target_id, target_config)
                
        except Exception as e:
            logger.error(f"Error in worker task: {e}")
    
    async def _distributed_worker_task(self, session_id: str):
        """Distributed worker task with resource monitoring"""
        try:
            while self.is_running:
                # Monitor resources
                if self._check_resource_limits():
                    await asyncio.sleep(5)
                    continue
                
                target_data = await self.load_balancer.get_next_target()
                if not target_data:
                    await asyncio.sleep(1)
                    continue
                
                target_id, target_config = target_data
                await self._process_target(session_id, target_id, target_config)
                
        except Exception as e:
            logger.error(f"Error in distributed worker task: {e}")
    
    async def _process_target(self, session_id: str, target_id: str, target_config: TargetConfig):
        """Process a single target"""
        try:
            session = self.active_sessions[session_id]
            
            # Update session status
            session.status[target_id].status = TargetStatus.SCANNING
            session.status[target_id].start_time = datetime.now()
            
            # Scan target
            scan_result = await self.target_manager.scan_target(target_id, target_config)
            
            # Update load balancer
            if scan_result.get('error'):
                self.load_balancer.fail_scan(target_id, scan_result['error'])
                session.failed_targets += 1
                session.status[target_id].status = TargetStatus.FAILED
            else:
                self.load_balancer.complete_scan(target_id, scan_result)
                session.completed_targets += 1
                session.status[target_id].status = TargetStatus.COMPLETED
            
            # Update progress
            session.overall_progress = (session.completed_targets + session.failed_targets) / session.total_targets
            
        except Exception as e:
            logger.error(f"Error processing target {target_id}: {e}")
            self.load_balancer.fail_scan(target_id, str(e))
            session.failed_targets += 1
            session.status[target_id].status = TargetStatus.FAILED
    
    def _check_resource_limits(self) -> bool:
        """Check if resource usage is within limits"""
        # Simple resource check - could be enhanced with actual system monitoring
        return False
    
    def _analyze_performance(self, session_id: str) -> Dict[str, Any]:
        """Analyze performance metrics for session"""
        try:
            session = self.active_sessions[session_id]
            
            completed_scans = [
                status for status in session.status.values()
                if status.status == TargetStatus.COMPLETED and status.end_time
            ]
            
            if not completed_scans:
                return {'avg_duration': 0, 'success_rate': 0}
            
            durations = [
                (status.end_time - status.start_time).total_seconds()
                for status in completed_scans
            ]
            
            return {
                'avg_duration': sum(durations) / len(durations),
                'success_rate': len(completed_scans) / session.total_targets,
                'total_duration': sum(durations)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing performance: {e}")
            return {'avg_duration': 0, 'success_rate': 0}
    
    async def _finalize_session(self, session_id: str, error: Optional[str] = None):
        """Finalize orchestration session"""
        try:
            session = self.active_sessions[session_id]
            session.end_time = datetime.now()
            
            # Calculate final metrics
            session.overall_progress = 1.0
            session.resource_usage = self.load_balancer.get_queue_status()['resource_usage']
            
            # Move to history
            self.session_history[session_id] = session
            del self.active_sessions[session_id]
            
            # Stop workers
            self.is_running = False
            for task in self.worker_tasks:
                task.cancel()
            
            logger.info(f"Finalized orchestration session {session_id}")
            
        except Exception as e:
            logger.error(f"Error finalizing session: {e}")
    
    def get_session_status(self, session_id: str) -> Optional[OrchestrationSession]:
        """Get status of orchestration session"""
        if session_id in self.active_sessions:
            return self.active_sessions[session_id]
        elif session_id in self.session_history:
            return self.session_history[session_id]
        return None
    
    def get_all_sessions(self) -> Dict[str, OrchestrationSession]:
        """Get all sessions (active and historical)"""
        all_sessions = {}
        all_sessions.update(self.active_sessions)
        all_sessions.update(self.session_history)
        return all_sessions
    
    def stop_session(self, session_id: str) -> bool:
        """Stop an active orchestration session"""
        try:
            if session_id in self.active_sessions:
                session = self.active_sessions[session_id]
                session.end_time = datetime.now()
                
                # Cancel all worker tasks
                for task in self.worker_tasks:
                    task.cancel()
                
                # Move to history
                self.session_history[session_id] = session
                del self.active_sessions[session_id]
                
                self.is_running = False
                logger.info(f"Stopped orchestration session {session_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error stopping session: {e}")
            return False
    
    def get_load_balancer_status(self) -> Dict[str, Any]:
        """Get load balancer status"""
        return self.load_balancer.get_queue_status()
    
    def get_target_manager_status(self) -> Dict[str, TargetStatus]:
        """Get target manager status"""
        return self.target_manager.get_all_target_statuses()

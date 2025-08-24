"""
Burp Suite Pro Client for automated security scanning
"""

import logging
import asyncio
import aiohttp
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
import json
import xml.etree.ElementTree as ET
from datetime import datetime

from app.core.config import settings

logger = logging.getLogger(__name__)


class BurpClient:
    """Client for Burp Suite Pro API"""
    
    def __init__(self):
        self.base_url = settings.burp_url
        self.api_key = settings.burp_api_key
        self.session = None
        self.site_map = {}
        self.scan_queue = []
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            headers={
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def _get_api_url(self, endpoint: str) -> str:
        """Get full API URL"""
        return urljoin(self.base_url, f"api/v1/{endpoint}")
    
    async def _make_request(self, method: str, endpoint: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make API request to Burp Suite Pro"""
        if not self.session:
            raise RuntimeError("Burp client not initialized. Use async context manager.")
        
        url = self._get_api_url(endpoint)
        
        try:
            if method.upper() == 'GET':
                async with self.session.get(url) as response:
                    response.raise_for_status()
                    return await response.json()
            elif method.upper() == 'POST':
                async with self.session.post(url, json=data) as response:
                    response.raise_for_status()
                    return await response.json()
            elif method.upper() == 'PUT':
                async with self.session.put(url, json=data) as response:
                    response.raise_for_status()
                    return await response.json()
            elif method.upper() == 'DELETE':
                async with self.session.delete(url) as response:
                    response.raise_for_status()
                    return await response.json()
        except aiohttp.ClientError as e:
            logger.error(f"Burp API request failed: {e}")
            raise
    
    async def check_connection(self) -> bool:
        """Check if Burp Suite Pro is accessible"""
        try:
            result = await self._make_request('GET', 'info')
            logger.info(f"Burp Suite Pro version: {result.get('version', 'Unknown')}")
            return True
        except Exception as e:
            logger.error(f"Burp Suite Pro connection failed: {e}")
            return False
    
    async def add_target_to_scope(self, target_url: str) -> bool:
        """Add target to Burp Suite Pro scope"""
        try:
            data = {
                'url': target_url,
                'include_in_scope': True
            }
            
            result = await self._make_request('POST', 'target/scope', data)
            logger.info(f"Added {target_url} to scope")
            return True
        except Exception as e:
            logger.error(f"Failed to add target to scope: {e}")
            return False
    
    async def start_spider_scan(self, target_url: str, max_depth: int = 5) -> str:
        """Start spider scan to crawl the target"""
        try:
            data = {
                'url': target_url,
                'max_depth': max_depth,
                'max_children': 10,
                'respect_robots_txt': False,
                'thread_count': 5
            }
            
            result = await self._make_request('POST', 'spider/scan', data)
            scan_id = result.get('scan_id')
            logger.info(f"Started spider scan: {scan_id}")
            return scan_id
        except Exception as e:
            logger.error(f"Failed to start spider scan: {e}")
            raise
    
    async def start_active_scan(self, target_url: str, scan_profile: str = "default") -> str:
        """Start active scan for vulnerabilities with custom profile"""
        try:
            # Define scan profiles
            scan_profiles = {
                "default": {
                    'scan_type': 'full',
                    'scan_scope': 'in_scope_only',
                    'insertion_points': ['all'],
                    'scan_checks': ['all']
                },
                "aggressive": {
                    'scan_type': 'full',
                    'scan_scope': 'in_scope_only',
                    'insertion_points': ['all'],
                    'scan_checks': ['all'],
                    'scan_speed': 'fast',
                    'max_requests_per_second': 50
                },
                "stealth": {
                    'scan_type': 'full',
                    'scan_scope': 'in_scope_only',
                    'insertion_points': ['all'],
                    'scan_checks': ['all'],
                    'scan_speed': 'slow',
                    'max_requests_per_second': 5,
                    'delay_between_requests': 1000
                },
                "api_focused": {
                    'scan_type': 'full',
                    'scan_scope': 'in_scope_only',
                    'insertion_points': ['json', 'xml', 'url'],
                    'scan_checks': ['injection', 'authentication', 'authorization']
                },
                "xss_focused": {
                    'scan_type': 'full',
                    'scan_scope': 'in_scope_only',
                    'insertion_points': ['url', 'body'],
                    'scan_checks': ['xss', 'reflected_xss', 'stored_xss']
                }
            }
            
            scan_config = scan_profiles.get(scan_profile, scan_profiles["default"])
            
            data = {
                'url': target_url,
                'scan_configuration': scan_profile,
                'application_logins': [],
                'scan_definition': scan_config
            }
            
            result = await self._make_request('POST', 'scan/active', data)
            scan_id = result.get('scan_id')
            logger.info(f"Started active scan with profile '{scan_profile}': {scan_id}")
            return scan_id
        except Exception as e:
            logger.error(f"Failed to start active scan: {e}")
            raise
    
    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status and progress"""
        try:
            result = await self._make_request('GET', f'scan/{scan_id}/status')
            return result
        except Exception as e:
            logger.error(f"Failed to get scan status: {e}")
            return {'status': 'unknown', 'progress': 0}
    
    async def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """Get detailed scan results"""
        try:
            result = await self._make_request('GET', f'scan/{scan_id}/results')
            return result
        except Exception as e:
            logger.error(f"Failed to get scan results: {e}")
            return {}
    
    async def get_issues(self, scan_id: str = None) -> List[Dict[str, Any]]:
        """Get security issues from scans"""
        try:
            endpoint = 'issues'
            if scan_id:
                endpoint = f'issues?scan_id={scan_id}'
            
            result = await self._make_request('GET', endpoint)
            return result.get('issues', [])
        except Exception as e:
            logger.error(f"Failed to get issues: {e}")
            return []
    
    async def start_scan(self, target_url: str, scan_types: List[str] = None) -> Dict[str, Any]:
        """Start comprehensive scan with multiple scan types"""
        if scan_types is None:
            scan_types = ['spider', 'active']
        
        try:
            # Add target to scope
            await self.add_target_to_scope(target_url)
            
            scan_results = {
                'target_url': target_url,
                'scan_start': datetime.now(),
                'scan_types': scan_types,
                'spider_scan_id': None,
                'active_scan_id': None,
                'issues': [],
                'status': 'running'
            }
            
            # Start spider scan if requested
            if 'spider' in scan_types:
                spider_scan_id = await self.start_spider_scan(target_url)
                scan_results['spider_scan_id'] = spider_scan_id
            
            # Start active scan if requested
            if 'active' in scan_types:
                active_scan_id = await self.start_active_scan(target_url)
                scan_results['active_scan_id'] = active_scan_id
            
            return scan_results
            
        except Exception as e:
            logger.error(f"Failed to start comprehensive scan: {e}")
            raise
    
    async def wait_for_scan_completion(self, scan_id: str, timeout: int = 3600) -> bool:
        """Wait for scan to complete"""
        start_time = datetime.now()
        
        while True:
            if (datetime.now() - start_time).total_seconds() > timeout:
                logger.warning(f"Scan {scan_id} timed out after {timeout} seconds")
                return False
            
            status = await self.get_scan_status(scan_id)
            if status.get('status') == 'completed':
                logger.info(f"Scan {scan_id} completed successfully")
                return True
            elif status.get('status') == 'failed':
                logger.error(f"Scan {scan_id} failed")
                return False
            
            # Wait before checking again
            await asyncio.sleep(10)
    
    async def get_site_map(self, target_url: str = None) -> Dict[str, Any]:
        """Get site map for target"""
        try:
            endpoint = 'target/sitemap'
            if target_url:
                endpoint = f'target/sitemap?url={target_url}'
            
            result = await self._make_request('GET', endpoint)
            return result
        except Exception as e:
            logger.error(f"Failed to get site map: {e}")
            return {}
    
    async def export_scan_report(self, scan_id: str, format: str = 'html') -> str:
        """Export scan report in specified format"""
        try:
            data = {
                'scan_id': scan_id,
                'format': format,
                'include_response_bodies': True,
                'include_request_bodies': True
            }
            
            result = await self._make_request('POST', 'report/export', data)
            report_url = result.get('report_url')
            
            if report_url:
                # Download the report
                async with self.session.get(report_url) as response:
                    report_content = await response.text()
                    return report_content
            
            return ""
        except Exception as e:
            logger.error(f"Failed to export scan report: {e}")
            return ""
    
    async def get_scan_statistics(self, scan_id: str) -> Dict[str, Any]:
        """Get scan statistics"""
        try:
            result = await self._make_request('GET', f'scan/{scan_id}/statistics')
            return result
        except Exception as e:
            logger.error(f"Failed to get scan statistics: {e}")
            return {}
    
    async def stop_scan(self, scan_id: str) -> bool:
        """Stop running scan"""
        try:
            await self._make_request('POST', f'scan/{scan_id}/stop')
            logger.info(f"Stopped scan {scan_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to stop scan: {e}")
            return False
    
    async def get_alerts(self, scan_id: str = None) -> List[Dict[str, Any]]:
        """Get security alerts from scans"""
        try:
            issues = await self.get_issues(scan_id)
            
            alerts = []
            for issue in issues:
                alert = {
                    'id': issue.get('id'),
                    'name': issue.get('name'),
                    'severity': issue.get('severity'),
                    'confidence': issue.get('confidence'),
                    'url': issue.get('url'),
                    'description': issue.get('description'),
                    'remediation': issue.get('remediation'),
                    'evidence': issue.get('evidence'),
                    'location': issue.get('location'),
                    'timestamp': issue.get('timestamp')
                }
                alerts.append(alert)
            
            return alerts
        except Exception as e:
            logger.error(f"Failed to get alerts: {e}")
            return []
    
    async def start_custom_scan(self, target_url: str, scan_config: Dict[str, Any]) -> str:
        """Start custom scan with specific configuration"""
        try:
            data = {
                'url': target_url,
                'scan_configuration': 'custom',
                'application_logins': scan_config.get('logins', []),
                'scan_definition': scan_config.get('definition', {}),
                'custom_headers': scan_config.get('headers', {}),
                'custom_payloads': scan_config.get('payloads', []),
                'scan_speed': scan_config.get('speed', 'normal'),
                'max_requests_per_second': scan_config.get('max_rps', 10)
            }
            
            result = await self._make_request('POST', 'scan/custom', data)
            scan_id = result.get('scan_id')
            logger.info(f"Started custom scan: {scan_id}")
            return scan_id
        except Exception as e:
            logger.error(f"Failed to start custom scan: {e}")
            raise
    
    async def get_scan_progress(self, scan_id: str) -> Dict[str, Any]:
        """Get detailed scan progress information"""
        try:
            result = await self._make_request('GET', f'scan/{scan_id}/progress')
            return {
                'scan_id': scan_id,
                'status': result.get('status'),
                'progress_percentage': result.get('progress', 0),
                'requests_sent': result.get('requests_sent', 0),
                'requests_remaining': result.get('requests_remaining', 0),
                'estimated_completion': result.get('estimated_completion'),
                'current_url': result.get('current_url'),
                'issues_found': result.get('issues_found', 0)
            }
        except Exception as e:
            logger.error(f"Failed to get scan progress: {e}")
            return {'status': 'unknown', 'progress_percentage': 0}
    
    async def pause_scan(self, scan_id: str) -> bool:
        """Pause a running scan"""
        try:
            await self._make_request('POST', f'scan/{scan_id}/pause')
            logger.info(f"Paused scan {scan_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to pause scan: {e}")
            return False
    
    async def resume_scan(self, scan_id: str) -> bool:
        """Resume a paused scan"""
        try:
            await self._make_request('POST', f'scan/{scan_id}/resume')
            logger.info(f"Resumed scan {scan_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to resume scan: {e}")
            return False
    
    async def get_scan_history(self, target_url: str = None) -> List[Dict[str, Any]]:
        """Get scan history for target"""
        try:
            endpoint = 'scan/history'
            if target_url:
                endpoint = f'scan/history?url={target_url}'
            
            result = await self._make_request('GET', endpoint)
            return result.get('scans', [])
        except Exception as e:
            logger.error(f"Failed to get scan history: {e}")
            return []
    
    async def compare_scans(self, scan_id_1: str, scan_id_2: str) -> Dict[str, Any]:
        """Compare two scans and show differences"""
        try:
            data = {
                'scan_id_1': scan_id_1,
                'scan_id_2': scan_id_2
            }
            
            result = await self._make_request('POST', 'scan/compare', data)
            return {
                'new_issues': result.get('new_issues', []),
                'fixed_issues': result.get('fixed_issues', []),
                'unchanged_issues': result.get('unchanged_issues', []),
                'improvement_score': result.get('improvement_score', 0)
            }
        except Exception as e:
            logger.error(f"Failed to compare scans: {e}")
            return {}
    
    async def export_scan_data(self, scan_id: str, format: str = 'json') -> str:
        """Export scan data in various formats"""
        try:
            data = {
                'scan_id': scan_id,
                'format': format,
                'include_requests': True,
                'include_responses': True,
                'include_evidence': True
            }
            
            result = await self._make_request('POST', 'scan/export', data)
            export_url = result.get('export_url')
            
            if export_url:
                async with self.session.get(export_url) as response:
                    return await response.text()
            
            return ""
        except Exception as e:
            logger.error(f"Failed to export scan data: {e}")
            return ""

"""
OWASP ZAP Client for automated security scanning
"""

import logging
import asyncio
import aiohttp
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
import json

from app.core.config import settings

logger = logging.getLogger(__name__)


class ZAPClient:
    """Client for OWASP ZAP API"""
    
    def __init__(self):
        self.base_url = settings.zap_url
        self.api_key = settings.zap_api_key
        self.session = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def _get_api_url(self, endpoint: str) -> str:
        """Get full API URL"""
        return urljoin(self.base_url, f"JSON/{endpoint}")
    
    async def _make_request(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make API request to ZAP"""
        if not self.session:
            raise RuntimeError("ZAP client not initialized. Use async context manager.")
        
        url = self._get_api_url(endpoint)
        if params is None:
            params = {}
        
        if self.api_key:
            params['apikey'] = self.api_key
        
        try:
            async with self.session.get(url, params=params) as response:
                response.raise_for_status()
                data = await response.json()
                return data
        except aiohttp.ClientError as e:
            logger.error(f"ZAP API request failed: {e}")
            raise
    
    async def check_connection(self) -> bool:
        """Check if ZAP is accessible"""
        try:
            result = await self._make_request("core/view/version")
            logger.info(f"ZAP version: {result.get('version', 'Unknown')}")
            return True
        except Exception as e:
            logger.error(f"ZAP connection failed: {e}")
            return False
    
    async def start_spider_scan(self, target_url: str, max_depth: int = 5) -> str:
        """Start spider scan to crawl the target"""
        try:
            params = {
                'url': target_url,
                'maxChildren': 10,
                'recurse': 'true',
                'contextName': '',
                'subtreeOnly': 'false'
            }
            
            result = await self._make_request("spider/action/scan", params)
            scan_id = result.get('scan')
            logger.info(f"Started spider scan: {scan_id}")
            return scan_id
        except Exception as e:
            logger.error(f"Failed to start spider scan: {e}")
            raise
    
    async def start_active_scan(self, target_url: str) -> str:
        """Start active scan for vulnerabilities"""
        try:
            params = {
                'url': target_url,
                'recurse': 'true',
                'inScopeOnly': 'false',
                'scanPolicyName': '',
                'method': 'GET',
                'postData': ''
            }
            
            result = await self._make_request("ascan/action/scan", params)
            scan_id = result.get('scan')
            logger.info(f"Started active scan: {scan_id}")
            return scan_id
        except Exception as e:
            logger.error(f"Failed to start active scan: {e}")
            raise
    
    async def get_scan_status(self, scan_id: str, scan_type: str = "spider") -> Dict[str, Any]:
        """Get scan status and progress"""
        try:
            if scan_type == "spider":
                endpoint = "spider/view/status"
            else:
                endpoint = "ascan/view/status"
            
            params = {'scanId': scan_id}
            result = await self._make_request(endpoint, params)
            return result
        except Exception as e:
            logger.error(f"Failed to get scan status: {e}")
            raise
    
    async def wait_for_scan_completion(self, scan_id: str, scan_type: str = "spider", timeout: int = 300) -> bool:
        """Wait for scan to complete"""
        start_time = asyncio.get_event_loop().time()
        
        while True:
            if asyncio.get_event_loop().time() - start_time > timeout:
                logger.warning(f"Scan timeout after {timeout} seconds")
                return False
            
            try:
                status = await self.get_scan_status(scan_id, scan_type)
                progress = int(status.get('status', 0))
                
                if progress >= 100:
                    logger.info(f"Scan {scan_id} completed")
                    return True
                
                logger.info(f"Scan progress: {progress}%")
                await asyncio.sleep(5)  # Wait 5 seconds before checking again
                
            except Exception as e:
                logger.error(f"Error checking scan status: {e}")
                return False
    
    async def get_alerts(self, base_url: str = None, risk_level: str = None) -> List[Dict[str, Any]]:
        """Get security alerts from ZAP"""
        try:
            params = {}
            if base_url:
                params['baseurl'] = base_url
            if risk_level:
                params['riskId'] = self._get_risk_id(risk_level)
            
            result = await self._make_request("core/view/alerts", params)
            alerts = result.get('alerts', [])
            
            # Filter and format alerts
            formatted_alerts = []
            for alert in alerts:
                formatted_alert = {
                    'id': alert.get('id'),
                    'name': alert.get('name'),
                    'risk': alert.get('risk'),
                    'confidence': alert.get('confidence'),
                    'url': alert.get('url'),
                    'parameter': alert.get('parameter'),
                    'evidence': alert.get('evidence'),
                    'description': alert.get('description'),
                    'solution': alert.get('solution'),
                    'reference': alert.get('reference'),
                    'cweid': alert.get('cweid'),
                    'wascid': alert.get('wascid')
                }
                formatted_alerts.append(formatted_alert)
            
            logger.info(f"Retrieved {len(formatted_alerts)} alerts")
            return formatted_alerts
            
        except Exception as e:
            logger.error(f"Failed to get alerts: {e}")
            raise
    
    def _get_risk_id(self, risk_level: str) -> str:
        """Convert risk level to ZAP risk ID"""
        risk_mapping = {
            'high': '3',
            'medium': '2', 
            'low': '1',
            'info': '0'
        }
        return risk_mapping.get(risk_level.lower(), '0')
    
    async def get_scan_summary(self, target_url: str) -> Dict[str, Any]:
        """Get comprehensive scan summary"""
        try:
            # Get alerts by risk level
            high_alerts = await self.get_alerts(target_url, 'high')
            medium_alerts = await self.get_alerts(target_url, 'medium')
            low_alerts = await self.get_alerts(target_url, 'low')
            info_alerts = await self.get_alerts(target_url, 'info')
            
            # Get site structure
            sites = await self._make_request("core/view/sites")
            
            summary = {
                'target_url': target_url,
                'scan_timestamp': asyncio.get_event_loop().time(),
                'alerts_summary': {
                    'high': len(high_alerts),
                    'medium': len(medium_alerts),
                    'low': len(low_alerts),
                    'info': len(info_alerts),
                    'total': len(high_alerts) + len(medium_alerts) + len(low_alerts) + len(info_alerts)
                },
                'alerts': {
                    'high': high_alerts,
                    'medium': medium_alerts,
                    'low': low_alerts,
                    'info': info_alerts
                },
                'sites': sites.get('sites', [])
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Failed to get scan summary: {e}")
            raise
    
    async def run_full_scan(self, target_url: str) -> Dict[str, Any]:
        """Run complete security scan (spider + active scan)"""
        try:
            logger.info(f"Starting full scan for: {target_url}")
            
            # Validate target URL
            if not self._is_allowed_domain(target_url):
                raise ValueError(f"Target URL {target_url} not in allowed domains")
            
            # Step 1: Spider scan
            logger.info("Starting spider scan...")
            spider_scan_id = await self.start_spider_scan(target_url)
            spider_completed = await self.wait_for_scan_completion(spider_scan_id, "spider")
            
            if not spider_completed:
                logger.warning("Spider scan did not complete, but continuing with active scan")
            
            # Step 2: Active scan
            logger.info("Starting active scan...")
            active_scan_id = await self.start_active_scan(target_url)
            active_completed = await self.wait_for_scan_completion(active_scan_id, "ascan")
            
            if not active_completed:
                logger.warning("Active scan did not complete within timeout")
            
            # Step 3: Get results
            logger.info("Collecting scan results...")
            summary = await self.get_scan_summary(target_url)
            
            # Add scan metadata
            summary['scan_metadata'] = {
                'spider_scan_id': spider_scan_id,
                'active_scan_id': active_scan_id,
                'spider_completed': spider_completed,
                'active_completed': active_completed
            }
            
            logger.info(f"Full scan completed. Found {summary['alerts_summary']['total']} alerts")
            return summary
            
        except Exception as e:
            logger.error(f"Full scan failed: {e}")
            raise
    
    def _is_allowed_domain(self, url: str) -> bool:
        """Check if URL domain is in allowed list"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.split(':')[0]  # Remove port if present
            
            for allowed_domain in settings.allowed_domains:
                if domain == allowed_domain or domain.endswith(f".{allowed_domain}"):
                    return True
            
            return False
        except Exception:
            return False
    
    async def get_scan_policies(self) -> List[Dict[str, Any]]:
        """Get available scan policies"""
        try:
            result = await self._make_request("ascan/view/scanPolicyNames")
            return result.get('policyNames', [])
        except Exception as e:
            logger.error(f"Failed to get scan policies: {e}")
            return []
    
    async def get_contexts(self) -> List[Dict[str, Any]]:
        """Get ZAP contexts"""
        try:
            result = await self._make_request("context/view/contextList")
            return result.get('contextList', [])
        except Exception as e:
            logger.error(f"Failed to get contexts: {e}")
            return []

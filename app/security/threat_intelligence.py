"""
Threat Intelligence Integration
Provides real-time threat intelligence, CVE analysis, and threat feed integration
"""

import asyncio
import logging
import aiohttp
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import re
from urllib.parse import urljoin, urlparse
import sqlite3
import os

from app.core.config import settings

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatSource(Enum):
    CVE_DATABASE = "cve_database"
    THREAT_FEEDS = "threat_feeds"
    MALWARE_ANALYSIS = "malware_analysis"
    VULNERABILITY_SCANNERS = "vulnerability_scanners"
    SOCIAL_MEDIA = "social_media"
    DARK_WEB = "dark_web"

@dataclass
class ThreatIndicator:
    indicator_type: str
    value: str
    threat_level: ThreatLevel
    confidence: float
    source: ThreatSource
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CVEInfo:
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    published_date: datetime
    last_modified: datetime
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    patch_available: bool = False

@dataclass
class ThreatReport:
    report_id: str
    timestamp: datetime
    target_url: str
    threat_indicators: List[ThreatIndicator] = field(default_factory=list)
    cve_findings: List[CVEInfo] = field(default_factory=list)
    risk_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    threat_trends: Dict[str, Any] = field(default_factory=dict)

class ThreatFeedManager:
    """Manages multiple threat intelligence feeds"""
    
    def __init__(self):
        self.feeds = {
            'abuseipdb': {
                'url': 'https://api.abuseipdb.com/api/v2/check',
                'api_key': getattr(settings, 'abuseipdb_api_key', None),
                'enabled': False
            },
            'virustotal': {
                'url': 'https://www.virustotal.com/vtapi/v2/url/report',
                'api_key': getattr(settings, 'virustotal_api_key', None),
                'enabled': False
            },
            'threatfox': {
                'url': 'https://threatfox-api.abuse.ch/api/v1/',
                'api_key': None,
                'enabled': True
            }
        }
        self.session = None
        self.cache_db = "data/threat_intelligence.db"
        self._init_cache()
    
    def _init_cache(self):
        """Initialize cache database"""
        try:
            os.makedirs(os.path.dirname(self.cache_db), exist_ok=True)
            conn = sqlite3.connect(self.cache_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator_type TEXT,
                    value TEXT,
                    threat_level TEXT,
                    confidence REAL,
                    source TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    tags TEXT,
                    metadata TEXT,
                    UNIQUE(indicator_type, value)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Threat intelligence cache initialized")
        except Exception as e:
            logger.error(f"Error initializing cache: {e}")
    
    async def get_session(self):
        """Get aiohttp session"""
        if self.session is None:
            self.session = aiohttp.ClientSession()
        return self.session
    
    async def check_ip_reputation(self, ip_address: str) -> Optional[ThreatIndicator]:
        """Check IP reputation across multiple feeds"""
        try:
            cached = self._get_cached_indicator('ip', ip_address)
            if cached and (datetime.now() - cached.last_seen).days < 1:
                return cached
            
            session = await self.get_session()
            threats = []
            
            # ThreatFox check
            if self.feeds['threatfox']['enabled']:
                threatfox_result = await self._check_threatfox(session, ip_address)
                if threatfox_result:
                    threats.append(threatfox_result)
            
            if threats:
                threat_indicator = self._aggregate_threats(threats, 'ip', ip_address)
                self._cache_indicator(threat_indicator)
                return threat_indicator
            
            return None
            
        except Exception as e:
            logger.error(f"Error checking IP reputation: {e}")
            return None
    
    async def check_domain_reputation(self, domain: str) -> Optional[ThreatIndicator]:
        """Check domain reputation"""
        try:
            cached = self._get_cached_indicator('domain', domain)
            if cached and (datetime.now() - cached.last_seen).days < 1:
                return cached
            
            session = await self.get_session()
            threats = []
            
            # VirusTotal check
            if self.feeds['virustotal']['enabled'] and self.feeds['virustotal']['api_key']:
                vt_result = await self._check_virustotal(session, domain)
                if vt_result:
                    threats.append(vt_result)
            
            if threats:
                threat_indicator = self._aggregate_threats(threats, 'domain', domain)
                self._cache_indicator(threat_indicator)
                return threat_indicator
            
            return None
            
        except Exception as e:
            logger.error(f"Error checking domain reputation: {e}")
            return None
    
    async def _check_virustotal(self, session: aiohttp.ClientSession, target: str) -> Optional[Dict]:
        """Check with VirusTotal"""
        try:
            feed = self.feeds['virustotal']
            params = {
                'apikey': feed['api_key'],
                'resource': target
            }
            
            async with session.get(feed['url'], params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('positives', 0) > 0:
                        total = data.get('total', 1)
                        ratio = data['positives'] / total
                        return {
                            'source': ThreatSource.THREAT_FEEDS,
                            'threat_level': self._score_to_level(ratio * 100),
                            'confidence': ratio,
                            'tags': ['malicious', 'virustotal']
                        }
            return None
        except Exception as e:
            logger.error(f"Error checking VirusTotal: {e}")
            return None
    
    async def _check_threatfox(self, session: aiohttp.ClientSession, ip_address: str) -> Optional[Dict]:
        """Check with ThreatFox"""
        try:
            feed = self.feeds['threatfox']
            payload = {
                "query": "search_ioc",
                "search_term": ip_address
            }
            
            async with session.post(feed['url'], json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('query_status') == 'ok' and data.get('data'):
                        return {
                            'source': ThreatSource.THREAT_FEEDS,
                            'threat_level': ThreatLevel.HIGH,
                            'confidence': 0.8,
                            'tags': ['malware', 'threatfox']
                        }
            return None
        except Exception as e:
            logger.error(f"Error checking ThreatFox: {e}")
            return None
    
    def _score_to_level(self, score: float) -> ThreatLevel:
        """Convert score to threat level"""
        if score >= 80:
            return ThreatLevel.CRITICAL
        elif score >= 60:
            return ThreatLevel.HIGH
        elif score >= 40:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _aggregate_threats(self, threats: List[Dict], indicator_type: str, value: str) -> ThreatIndicator:
        """Aggregate multiple threat sources"""
        if not threats:
            return None
        
        total_confidence = sum(t['confidence'] for t in threats)
        avg_confidence = total_confidence / len(threats)
        
        threat_levels = [ThreatLevel.CRITICAL, ThreatLevel.HIGH, ThreatLevel.MEDIUM, ThreatLevel.LOW]
        max_level = ThreatLevel.LOW
        for threat in threats:
            if threat['threat_level'].value > max_level.value:
                max_level = threat['threat_level']
        
        all_tags = []
        for threat in threats:
            all_tags.extend(threat.get('tags', []))
        
        return ThreatIndicator(
            indicator_type=indicator_type,
            value=value,
            threat_level=max_level,
            confidence=avg_confidence,
            source=ThreatSource.THREAT_FEEDS,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            tags=list(set(all_tags))
        )
    
    def _get_cached_indicator(self, indicator_type: str, value: str) -> Optional[ThreatIndicator]:
        """Get cached threat indicator"""
        try:
            conn = sqlite3.connect(self.cache_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM threat_indicators 
                WHERE indicator_type = ? AND value = ?
            ''', (indicator_type, value))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return ThreatIndicator(
                    indicator_type=row[1],
                    value=row[2],
                    threat_level=ThreatLevel(row[3]),
                    confidence=row[4],
                    source=ThreatSource(row[5]),
                    first_seen=datetime.fromisoformat(row[6]),
                    last_seen=datetime.fromisoformat(row[7]),
                    tags=json.loads(row[8]) if row[8] else [],
                    metadata=json.loads(row[9]) if row[9] else {}
                )
            return None
        except Exception as e:
            logger.error(f"Error getting cached indicator: {e}")
            return None
    
    def _cache_indicator(self, indicator: ThreatIndicator):
        """Cache threat indicator"""
        try:
            conn = sqlite3.connect(self.cache_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO threat_indicators 
                (indicator_type, value, threat_level, confidence, source, first_seen, last_seen, tags, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                indicator.indicator_type,
                indicator.value,
                indicator.threat_level.value,
                indicator.confidence,
                indicator.source.value,
                indicator.first_seen.isoformat(),
                indicator.last_seen.isoformat(),
                json.dumps(indicator.tags),
                json.dumps(indicator.metadata)
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error caching indicator: {e}")

class ThreatIntelligenceService:
    """Main threat intelligence service"""
    
    def __init__(self):
        self.threat_feed_manager = ThreatFeedManager()
        logger.info("Threat Intelligence Service initialized")
    
    async def analyze_target(self, target_url: str) -> ThreatReport:
        """Analyze target for threats"""
        try:
            report_id = f"threat_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hashlib.md5(target_url.encode()).hexdigest()[:8]}"
            
            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc
            ip_address = None
            
            try:
                import socket
                ip_address = socket.gethostbyname(domain)
            except:
                pass
            
            threat_indicators = []
            
            # Check domain reputation
            if domain:
                domain_threat = await self.threat_feed_manager.check_domain_reputation(domain)
                if domain_threat:
                    threat_indicators.append(domain_threat)
            
            # Check IP reputation
            if ip_address:
                ip_threat = await self.threat_feed_manager.check_ip_reputation(ip_address)
                if ip_threat:
                    threat_indicators.append(ip_threat)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(threat_indicators)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(threat_indicators, risk_score)
            
            # Analyze threat trends
            threat_trends = self._analyze_threat_trends(threat_indicators)
            
            return ThreatReport(
                report_id=report_id,
                timestamp=datetime.now(),
                target_url=target_url,
                threat_indicators=threat_indicators,
                risk_score=risk_score,
                recommendations=recommendations,
                threat_trends=threat_trends
            )
            
        except Exception as e:
            logger.error(f"Error analyzing target: {e}")
            return None
    
    def _calculate_risk_score(self, threat_indicators: List[ThreatIndicator]) -> float:
        """Calculate overall risk score"""
        risk_score = 0.0
        
        for indicator in threat_indicators:
            if indicator.threat_level == ThreatLevel.CRITICAL:
                risk_score += 0.4
            elif indicator.threat_level == ThreatLevel.HIGH:
                risk_score += 0.3
            elif indicator.threat_level == ThreatLevel.MEDIUM:
                risk_score += 0.2
            elif indicator.threat_level == ThreatLevel.LOW:
                risk_score += 0.1
        
        return min(risk_score, 1.0)
    
    def _generate_recommendations(self, threat_indicators: List[ThreatIndicator], risk_score: float) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if risk_score > 0.8:
            recommendations.append("CRITICAL: Immediate action required - high threat level detected")
            recommendations.append("Implement emergency security controls")
            recommendations.append("Consider system isolation if necessary")
        
        if threat_indicators:
            recommendations.append("Monitor threat indicators regularly")
            recommendations.append("Implement threat intelligence feeds")
        
        if not recommendations:
            recommendations.append("Continue regular security monitoring")
            recommendations.append("Implement defense-in-depth security strategy")
        
        return recommendations
    
    def _analyze_threat_trends(self, threat_indicators: List[ThreatIndicator]) -> Dict[str, Any]:
        """Analyze threat trends"""
        trends = {
            'threat_level_distribution': {},
            'recent_activity': {},
            'emerging_threats': []
        }
        
        for indicator in threat_indicators:
            level = indicator.threat_level.value
            trends['threat_level_distribution'][level] = trends['threat_level_distribution'].get(level, 0) + 1
        
        trends['recent_activity']['total_indicators'] = len(threat_indicators)
        
        high_threat_indicators = [ind for ind in threat_indicators if ind.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]]
        trends['emerging_threats'] = [ind.value for ind in high_threat_indicators[:5]]
        
        return trends

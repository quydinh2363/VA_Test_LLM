"""
Advanced Reporting and Analytics
Provides AI-powered vulnerability analysis, risk scoring, and executive dashboards
"""

import asyncio
import logging
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from io import BytesIO
import base64
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

from app.core.config import settings
from app.security.threat_intelligence import ThreatIntelligenceService, ThreatLevel

logger = logging.getLogger(__name__)

class ReportType(Enum):
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAILED = "technical_detailed"
    COMPLIANCE = "compliance"
    TREND_ANALYSIS = "trend_analysis"
    COMPARATIVE = "comparative"

class RiskCategory(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class VulnerabilityMetrics:
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    risk_score: float = 0.0
    remediation_effort: str = "low"
    business_impact: str = "low"
    compliance_status: Dict[str, bool] = field(default_factory=dict)

@dataclass
class TrendData:
    period: str
    vulnerability_count: int
    risk_score: float
    new_vulnerabilities: int
    remediated_vulnerabilities: int
    trend_direction: str

@dataclass
class ExecutiveDashboard:
    dashboard_id: str
    timestamp: datetime
    overall_risk_score: float
    risk_level: str
    key_metrics: Dict[str, Any]
    top_vulnerabilities: List[Dict]
    compliance_status: Dict[str, Any]
    recommendations: List[str]
    charts_data: Dict[str, Any]

class RiskScoringEngine:
    """Advanced risk scoring with multiple algorithms"""
    
    def __init__(self):
        self.weights = {
            'cvss_score': 0.3,
            'exploit_availability': 0.2,
            'patch_availability': 0.15,
            'business_impact': 0.2,
            'threat_intelligence': 0.15
        }
    
    def calculate_vulnerability_risk(self, vulnerability: Dict) -> float:
        """Calculate risk score for individual vulnerability"""
        risk_score = 0.0
        
        # CVSS Score contribution
        cvss_score = vulnerability.get('cvss_score', 0.0)
        risk_score += (cvss_score / 10.0) * self.weights['cvss_score']
        
        # Exploit availability
        if vulnerability.get('exploit_available', False):
            risk_score += self.weights['exploit_availability']
        
        # Patch availability
        if not vulnerability.get('patch_available', True):
            risk_score += self.weights['patch_availability']
        
        # Business impact
        business_impact = vulnerability.get('business_impact', 'low')
        impact_scores = {'low': 0.1, 'medium': 0.5, 'high': 1.0}
        risk_score += impact_scores.get(business_impact, 0.1) * self.weights['business_impact']
        
        # Threat intelligence
        threat_level = vulnerability.get('threat_level', 'low')
        threat_scores = {'low': 0.1, 'medium': 0.3, 'high': 0.7, 'critical': 1.0}
        risk_score += threat_scores.get(threat_level, 0.1) * self.weights['threat_intelligence']
        
        return min(risk_score, 1.0)
    
    def calculate_overall_risk(self, vulnerabilities: List[Dict]) -> float:
        """Calculate overall risk score for all vulnerabilities"""
        if not vulnerabilities:
            return 0.0
        
        # Calculate individual risk scores
        risk_scores = [self.calculate_vulnerability_risk(vuln) for vuln in vulnerabilities]
        
        # Use weighted average with higher weights for higher risk vulnerabilities
        weights = []
        for score in risk_scores:
            if score >= 0.8:
                weights.append(2.0)  # Critical vulnerabilities get double weight
            elif score >= 0.6:
                weights.append(1.5)  # High vulnerabilities get 1.5x weight
            else:
                weights.append(1.0)
        
        # Calculate weighted average
        total_weight = sum(weights)
        if total_weight == 0:
            return 0.0
        
        weighted_sum = sum(score * weight for score, weight in zip(risk_scores, weights))
        overall_risk = weighted_sum / total_weight
        
        return min(overall_risk, 1.0)
    
    def categorize_risk_level(self, risk_score: float) -> str:
        """Categorize risk score into risk level"""
        if risk_score >= 0.8:
            return "Critical"
        elif risk_score >= 0.6:
            return "High"
        elif risk_score >= 0.4:
            return "Medium"
        elif risk_score >= 0.2:
            return "Low"
        else:
            return "Info"

class VulnerabilityAnalyzer:
    """AI-powered vulnerability analysis"""
    
    def __init__(self):
        self.threat_intelligence = ThreatIntelligenceService()
        self.risk_scoring = RiskScoringEngine()
    
    async def analyze_vulnerabilities(self, vulnerabilities: List[Dict], target_url: str) -> VulnerabilityMetrics:
        """Analyze vulnerabilities with AI insights"""
        try:
            # Get threat intelligence
            threat_report = await self.threat_intelligence.analyze_target(target_url)
            
            # Enhance vulnerabilities with threat intelligence
            enhanced_vulnerabilities = []
            for vuln in vulnerabilities:
                enhanced_vuln = vuln.copy()
                
                # Add threat intelligence data
                if threat_report and threat_report.threat_indicators:
                    enhanced_vuln['threat_level'] = self._get_highest_threat_level(threat_report.threat_indicators)
                    enhanced_vuln['threat_indicators'] = len(threat_report.threat_indicators)
                else:
                    enhanced_vuln['threat_level'] = 'low'
                    enhanced_vuln['threat_indicators'] = 0
                
                # Calculate business impact
                enhanced_vuln['business_impact'] = self._assess_business_impact(vuln)
                
                # Check compliance
                enhanced_vuln['compliance_impact'] = self._check_compliance_impact(vuln)
                
                enhanced_vulnerabilities.append(enhanced_vuln)
            
            # Calculate metrics
            metrics = self._calculate_metrics(enhanced_vulnerabilities)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error analyzing vulnerabilities: {e}")
            return VulnerabilityMetrics()
    
    def _get_highest_threat_level(self, threat_indicators: List) -> str:
        """Get highest threat level from indicators"""
        if not threat_indicators:
            return 'low'
        
        threat_levels = [ind.threat_level.value for ind in threat_indicators]
        if 'critical' in threat_levels:
            return 'critical'
        elif 'high' in threat_levels:
            return 'high'
        elif 'medium' in threat_levels:
            return 'medium'
        else:
            return 'low'
    
    def _assess_business_impact(self, vulnerability: Dict) -> str:
        """Assess business impact of vulnerability"""
        # Simple heuristic based on vulnerability type and severity
        vuln_type = vulnerability.get('type', '').lower()
        severity = vulnerability.get('severity', 'low').lower()
        
        high_impact_types = ['sql injection', 'xss', 'rce', 'authentication bypass']
        medium_impact_types = ['csrf', 'xxe', 'ssrf', 'information disclosure']
        
        if any(impact_type in vuln_type for impact_type in high_impact_types):
            return 'high'
        elif any(impact_type in vuln_type for impact_type in medium_impact_types):
            return 'medium'
        else:
            return 'low'
    
    def _check_compliance_impact(self, vulnerability: Dict) -> Dict[str, bool]:
        """Check compliance impact"""
        compliance_standards = {
            'owasp_top_10': False,
            'pci_dss': False,
            'sox': False,
            'gdpr': False
        }
        
        vuln_type = vulnerability.get('type', '').lower()
        severity = vulnerability.get('severity', 'low').lower()
        
        # OWASP Top 10 mapping
        owasp_mappings = {
            'sql injection': 'injection',
            'xss': 'xss',
            'authentication bypass': 'broken_authentication',
            'csrf': 'broken_authentication',
            'xxe': 'xml_external_entity',
            'ssrf': 'security_misconfiguration'
        }
        
        for vuln_pattern, owasp_category in owasp_mappings.items():
            if vuln_pattern in vuln_type:
                compliance_standards['owasp_top_10'] = True
                break
        
        # PCI DSS impact for high severity vulnerabilities
        if severity in ['high', 'critical']:
            compliance_standards['pci_dss'] = True
        
        return compliance_standards
    
    def _calculate_metrics(self, vulnerabilities: List[Dict]) -> VulnerabilityMetrics:
        """Calculate comprehensive metrics"""
        metrics = VulnerabilityMetrics()
        
        metrics.total_vulnerabilities = len(vulnerabilities)
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity == 'critical':
                metrics.critical_count += 1
            elif severity == 'high':
                metrics.high_count += 1
            elif severity == 'medium':
                metrics.medium_count += 1
            elif severity == 'low':
                metrics.low_count += 1
            else:
                metrics.info_count += 1
        
        # Calculate risk score
        metrics.risk_score = self.risk_scoring.calculate_overall_risk(vulnerabilities)
        
        # Determine remediation effort
        if metrics.critical_count > 0 or metrics.high_count > 5:
            metrics.remediation_effort = "high"
        elif metrics.high_count > 0 or metrics.medium_count > 10:
            metrics.remediation_effort = "medium"
        else:
            metrics.remediation_effort = "low"
        
        # Determine business impact
        high_impact_count = sum(1 for vuln in vulnerabilities if vuln.get('business_impact') == 'high')
        if high_impact_count > 0:
            metrics.business_impact = "high"
        elif high_impact_count > 0 or metrics.critical_count > 0:
            metrics.business_impact = "medium"
        else:
            metrics.business_impact = "low"
        
        return metrics

class ChartGenerator:
    """Generate interactive charts and visualizations"""
    
    def __init__(self):
        self.colors = {
            'critical': '#FF0000',
            'high': '#FF6600',
            'medium': '#FFCC00',
            'low': '#00CC00',
            'info': '#0066CC'
        }
    
    def generate_vulnerability_distribution(self, metrics: VulnerabilityMetrics) -> str:
        """Generate vulnerability distribution chart"""
        try:
            labels = ['Critical', 'High', 'Medium', 'Low', 'Info']
            values = [metrics.critical_count, metrics.high_count, 
                     metrics.medium_count, metrics.low_count, metrics.info_count]
            colors = [self.colors['critical'], self.colors['high'], 
                     self.colors['medium'], self.colors['low'], self.colors['info']]
            
            fig = go.Figure(data=[go.Pie(labels=labels, values=values, marker_colors=colors)])
            fig.update_layout(
                title="Vulnerability Distribution by Severity",
                height=400
            )
            
            return self._fig_to_html(fig)
        except Exception as e:
            logger.error(f"Error generating vulnerability distribution chart: {e}")
            return ""
    
    def generate_risk_trend(self, trend_data: List[TrendData]) -> str:
        """Generate risk trend chart"""
        try:
            periods = [data.period for data in trend_data]
            risk_scores = [data.risk_score for data in trend_data]
            vuln_counts = [data.vulnerability_count for data in trend_data]
            
            fig = make_subplots(specs=[[{"secondary_y": True}]])
            
            fig.add_trace(
                go.Scatter(x=periods, y=risk_scores, name="Risk Score", line=dict(color='red')),
                secondary_y=False
            )
            
            fig.add_trace(
                go.Bar(x=periods, y=vuln_counts, name="Vulnerability Count", marker_color='blue'),
                secondary_y=True
            )
            
            fig.update_layout(
                title="Risk Score and Vulnerability Count Trends",
                height=400
            )
            
            return self._fig_to_html(fig)
        except Exception as e:
            logger.error(f"Error generating risk trend chart: {e}")
            return ""
    
    def generate_compliance_dashboard(self, compliance_data: Dict[str, Any]) -> str:
        """Generate compliance dashboard"""
        try:
            standards = list(compliance_data.keys())
            compliance_scores = list(compliance_data.values())
            
            fig = go.Figure(data=[
                go.Bar(x=standards, y=compliance_scores, 
                      marker_color=['green' if score >= 80 else 'orange' if score >= 60 else 'red' 
                                  for score in compliance_scores])
            ])
            
            fig.update_layout(
                title="Compliance Status by Standard",
                yaxis_title="Compliance Score (%)",
                height=400
            )
            
            return self._fig_to_html(fig)
        except Exception as e:
            logger.error(f"Error generating compliance dashboard: {e}")
            return ""
    
    def _fig_to_html(self, fig) -> str:
        """Convert plotly figure to HTML string"""
        try:
            return fig.to_html(include_plotlyjs=False, full_html=False)
        except Exception as e:
            logger.error(f"Error converting figure to HTML: {e}")
            return ""

class AdvancedReportingService:
    """Main advanced reporting service"""
    
    def __init__(self):
        self.vulnerability_analyzer = VulnerabilityAnalyzer()
        self.chart_generator = ChartGenerator()
        self.risk_scoring = RiskScoringEngine()
        logger.info("Advanced Reporting Service initialized")
    
    async def generate_executive_dashboard(self, vulnerabilities: List[Dict], 
                                         target_url: str, 
                                         historical_data: Optional[List[Dict]] = None) -> ExecutiveDashboard:
        """Generate comprehensive executive dashboard"""
        try:
            dashboard_id = f"dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hashlib.md5(target_url.encode()).hexdigest()[:8]}"
            
            # Analyze vulnerabilities
            metrics = await self.vulnerability_analyzer.analyze_vulnerabilities(vulnerabilities, target_url)
            
            # Calculate overall risk
            overall_risk_score = self.risk_scoring.calculate_overall_risk(vulnerabilities)
            risk_level = self.risk_scoring.categorize_risk_level(overall_risk_score)
            
            # Generate key metrics
            key_metrics = {
                'total_vulnerabilities': metrics.total_vulnerabilities,
                'critical_vulnerabilities': metrics.critical_count,
                'high_vulnerabilities': metrics.high_count,
                'risk_score': overall_risk_score,
                'remediation_effort': metrics.remediation_effort,
                'business_impact': metrics.business_impact
            }
            
            # Get top vulnerabilities
            top_vulnerabilities = self._get_top_vulnerabilities(vulnerabilities, limit=5)
            
            # Generate compliance status
            compliance_status = self._generate_compliance_status(vulnerabilities)
            
            # Generate recommendations
            recommendations = self._generate_executive_recommendations(metrics, overall_risk_score)
            
            # Generate charts
            charts_data = {
                'vulnerability_distribution': self.chart_generator.generate_vulnerability_distribution(metrics),
                'compliance_dashboard': self.chart_generator.generate_compliance_dashboard(compliance_status)
            }
            
            # Add trend analysis if historical data available
            if historical_data:
                trend_data = self._analyze_trends(historical_data)
                charts_data['risk_trend'] = self.chart_generator.generate_risk_trend(trend_data)
            
            return ExecutiveDashboard(
                dashboard_id=dashboard_id,
                timestamp=datetime.now(),
                overall_risk_score=overall_risk_score,
                risk_level=risk_level,
                key_metrics=key_metrics,
                top_vulnerabilities=top_vulnerabilities,
                compliance_status=compliance_status,
                recommendations=recommendations,
                charts_data=charts_data
            )
            
        except Exception as e:
            logger.error(f"Error generating executive dashboard: {e}")
            return None
    
    def _get_top_vulnerabilities(self, vulnerabilities: List[Dict], limit: int = 5) -> List[Dict]:
        """Get top vulnerabilities by risk score"""
        try:
            # Calculate risk scores for all vulnerabilities
            scored_vulnerabilities = []
            for vuln in vulnerabilities:
                risk_score = self.risk_scoring.calculate_vulnerability_risk(vuln)
                scored_vuln = vuln.copy()
                scored_vuln['calculated_risk_score'] = risk_score
                scored_vulnerabilities.append(scored_vuln)
            
            # Sort by risk score and return top ones
            sorted_vulns = sorted(scored_vulnerabilities, 
                                key=lambda x: x['calculated_risk_score'], reverse=True)
            
            return sorted_vulns[:limit]
        except Exception as e:
            logger.error(f"Error getting top vulnerabilities: {e}")
            return []
    
    def _generate_compliance_status(self, vulnerabilities: List[Dict]) -> Dict[str, float]:
        """Generate compliance status for different standards"""
        compliance_scores = {
            'OWASP Top 10': 0.0,
            'PCI DSS': 0.0,
            'SOX': 0.0,
            'GDPR': 0.0
        }
        
        try:
            total_vulns = len(vulnerabilities)
            if total_vulns == 0:
                return {k: 100.0 for k in compliance_scores.keys()}
            
            # Count compliance violations
            owasp_violations = sum(1 for vuln in vulnerabilities 
                                 if vuln.get('compliance_impact', {}).get('owasp_top_10', False))
            pci_violations = sum(1 for vuln in vulnerabilities 
                               if vuln.get('compliance_impact', {}).get('pci_dss', False))
            sox_violations = sum(1 for vuln in vulnerabilities 
                               if vuln.get('compliance_impact', {}).get('sox', False))
            gdpr_violations = sum(1 for vuln in vulnerabilities 
                                if vuln.get('compliance_impact', {}).get('gdpr', False))
            
            # Calculate compliance scores
            compliance_scores['OWASP Top 10'] = max(0, 100 - (owasp_violations / total_vulns * 100))
            compliance_scores['PCI DSS'] = max(0, 100 - (pci_violations / total_vulns * 100))
            compliance_scores['SOX'] = max(0, 100 - (sox_violations / total_vulns * 100))
            compliance_scores['GDPR'] = max(0, 100 - (gdpr_violations / total_vulns * 100))
            
            return compliance_scores
        except Exception as e:
            logger.error(f"Error generating compliance status: {e}")
            return compliance_scores
    
    def _generate_executive_recommendations(self, metrics: VulnerabilityMetrics, 
                                          risk_score: float) -> List[str]:
        """Generate executive-level recommendations"""
        recommendations = []
        
        if risk_score >= 0.8:
            recommendations.append("🚨 CRITICAL: Immediate action required - implement emergency security controls")
            recommendations.append("🔒 Isolate affected systems and implement containment measures")
            recommendations.append("👥 Conduct executive security briefing within 24 hours")
        
        if metrics.critical_count > 0:
            recommendations.append("⚡ Prioritize critical vulnerability remediation - allocate dedicated resources")
            recommendations.append("📊 Implement real-time security monitoring for critical systems")
        
        if metrics.high_count > 5:
            recommendations.append("🛡️ Establish dedicated security team for high-priority remediation")
            recommendations.append("📈 Increase security budget allocation for vulnerability management")
        
        if metrics.remediation_effort == "high":
            recommendations.append("💼 Consider engaging external security consultants for remediation support")
            recommendations.append("⏰ Establish aggressive remediation timeline with weekly progress reviews")
        
        if metrics.business_impact == "high":
            recommendations.append("🏢 Conduct business impact assessment for affected systems")
            recommendations.append("📋 Update business continuity plans based on security findings")
        
        # Always include general recommendations
        recommendations.append("📚 Implement comprehensive security awareness training program")
        recommendations.append("🔍 Establish regular security assessment schedule")
        recommendations.append("📊 Develop security metrics dashboard for ongoing monitoring")
        
        return recommendations
    
    def _analyze_trends(self, historical_data: List[Dict]) -> List[TrendData]:
        """Analyze trends from historical data"""
        try:
            trend_data = []
            
            # Group data by period (monthly for this example)
            for i, data_point in enumerate(historical_data[-12:]):  # Last 12 months
                trend_data.append(TrendData(
                    period=data_point.get('period', f"Month {i+1}"),
                    vulnerability_count=data_point.get('total_vulnerabilities', 0),
                    risk_score=data_point.get('risk_score', 0.0),
                    new_vulnerabilities=data_point.get('new_vulnerabilities', 0),
                    remediated_vulnerabilities=data_point.get('remediated_vulnerabilities', 0),
                    trend_direction=self._calculate_trend_direction(data_point, historical_data[i-1] if i > 0 else None)
                ))
            
            return trend_data
        except Exception as e:
            logger.error(f"Error analyzing trends: {e}")
            return []
    
    def _calculate_trend_direction(self, current: Dict, previous: Optional[Dict]) -> str:
        """Calculate trend direction"""
        if not previous:
            return "stable"
        
        current_risk = current.get('risk_score', 0.0)
        previous_risk = previous.get('risk_score', 0.0)
        
        if current_risk > previous_risk + 0.1:
            return "increasing"
        elif current_risk < previous_risk - 0.1:
            return "decreasing"
        else:
            return "stable"

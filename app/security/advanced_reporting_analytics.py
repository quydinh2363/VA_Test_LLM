"""
Advanced Reporting & Analytics Module
Real-time dashboards, predictive analytics, and compliance automation
"""
import asyncio
import json
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import structlog

logger = structlog.get_logger()

class DashboardType(Enum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"
    REAL_TIME = "real_time"
    PREDICTIVE = "predictive"

class AnalyticsType(Enum):
    TREND_ANALYSIS = "trend_analysis"
    ANOMALY_DETECTION = "anomaly_detection"
    PREDICTIVE_MODELING = "predictive_modeling"
    CLUSTER_ANALYSIS = "cluster_analysis"
    RISK_SCORING = "risk_scoring"

class ComplianceStandard(Enum):
    OWASP_TOP_10 = "owasp_top_10"
    PCI_DSS = "pci_dss"
    SOX = "sox"
    GDPR = "gdpr"
    ISO_27001 = "iso_27001"
    NIST = "nist"

@dataclass
class DashboardConfig:
    dashboard_id: str
    dashboard_type: DashboardType
    refresh_interval: int
    data_sources: List[str]
    widgets: List[Dict[str, Any]]
    filters: Dict[str, Any]

@dataclass
class AnalyticsResult:
    analysis_id: str
    analysis_type: AnalyticsType
    target_data: str
    results: Dict[str, Any]
    confidence: float
    recommendations: List[str]
    timestamp: datetime

@dataclass
class ComplianceReport:
    report_id: str
    standard: ComplianceStandard
    assessment_date: datetime
    compliance_score: float
    findings: List[Dict[str, Any]]
    recommendations: List[str]
    next_assessment: datetime

class RealTimeDashboard:
    """Real-time dashboard with live monitoring and alerting"""
    
    def __init__(self):
        self.dashboards = {}
        self.data_streams = {}
        self.alerts = []
        self.metrics_history = []
        
    def create_dashboard(self, dashboard_type: DashboardType, 
                        refresh_interval: int = 30) -> DashboardConfig:
        """Create a new dashboard"""
        dashboard_id = f"dashboard_{dashboard_type.value}_{int(time.time())}"
        
        # Get default widgets for dashboard type
        widgets = self._get_default_widgets(dashboard_type)
        
        dashboard = DashboardConfig(
            dashboard_id=dashboard_id,
            dashboard_type=dashboard_type,
            refresh_interval=refresh_interval,
            data_sources=[],
            widgets=widgets,
            filters={}
        )
        
        self.dashboards[dashboard_id] = dashboard
        return dashboard
    
    def _get_default_widgets(self, dashboard_type: DashboardType) -> List[Dict[str, Any]]:
        """Get default widgets for dashboard type"""
        if dashboard_type == DashboardType.EXECUTIVE:
            return [
                {'type': 'risk_score', 'title': 'Overall Risk Score', 'size': 'large'},
                {'type': 'vulnerability_trend', 'title': 'Vulnerability Trends', 'size': 'medium'},
                {'type': 'compliance_status', 'title': 'Compliance Status', 'size': 'medium'},
                {'type': 'threat_alerts', 'title': 'Active Threats', 'size': 'small'}
            ]
        elif dashboard_type == DashboardType.TECHNICAL:
            return [
                {'type': 'vulnerability_distribution', 'title': 'Vulnerability Distribution', 'size': 'large'},
                {'type': 'attack_timeline', 'title': 'Attack Timeline', 'size': 'medium'},
                {'type': 'system_status', 'title': 'System Status', 'size': 'medium'},
                {'type': 'performance_metrics', 'title': 'Performance Metrics', 'size': 'small'}
            ]
        elif dashboard_type == DashboardType.REAL_TIME:
            return [
                {'type': 'live_attacks', 'title': 'Live Attack Monitoring', 'size': 'large'},
                {'type': 'system_health', 'title': 'System Health', 'size': 'medium'},
                {'type': 'network_traffic', 'title': 'Network Traffic', 'size': 'medium'},
                {'type': 'alert_feed', 'title': 'Real-time Alerts', 'size': 'small'}
            ]
        else:
            return [
                {'type': 'basic_metrics', 'title': 'Basic Metrics', 'size': 'medium'}
            ]
    
    async def update_dashboard_data(self, dashboard_id: str, new_data: Dict[str, Any]):
        """Update dashboard with new data"""
        dashboard = self.dashboards.get(dashboard_id)
        if not dashboard:
            return
        
        # Store data in history
        self.metrics_history.append({
            'dashboard_id': dashboard_id,
            'timestamp': datetime.now(),
            'data': new_data
        })
        
        # Check for alerts
        alerts = self._check_for_alerts(dashboard_id, new_data)
        if alerts:
            self.alerts.extend(alerts)
        
        # Update data streams
        self.data_streams[dashboard_id] = {
            'last_update': datetime.now(),
            'data': new_data,
            'alerts': alerts
        }
    
    def _check_for_alerts(self, dashboard_id: str, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for alerts based on data"""
        alerts = []
        
        # Check risk score alerts
        risk_score = data.get('risk_score', 0)
        if risk_score > 8.0:
            alerts.append({
                'type': 'high_risk',
                'severity': 'critical',
                'message': f'High risk score detected: {risk_score}',
                'timestamp': datetime.now(),
                'dashboard_id': dashboard_id
            })
        
        # Check vulnerability alerts
        new_vulnerabilities = data.get('new_vulnerabilities', 0)
        if new_vulnerabilities > 5:
            alerts.append({
                'type': 'vulnerability_spike',
                'severity': 'high',
                'message': f'Vulnerability spike detected: {new_vulnerabilities} new vulnerabilities',
                'timestamp': datetime.now(),
                'dashboard_id': dashboard_id
            })
        
        # Check compliance alerts
        compliance_score = data.get('compliance_score', 100)
        if compliance_score < 80:
            alerts.append({
                'type': 'compliance_breach',
                'severity': 'medium',
                'message': f'Compliance score below threshold: {compliance_score}%',
                'timestamp': datetime.now(),
                'dashboard_id': dashboard_id
            })
        
        return alerts
    
    def get_dashboard_data(self, dashboard_id: str) -> Dict[str, Any]:
        """Get current dashboard data"""
        dashboard = self.dashboards.get(dashboard_id)
        if not dashboard:
            return {'error': 'Dashboard not found'}
        
        data_stream = self.data_streams.get(dashboard_id, {})
        
        return {
            'dashboard_id': dashboard_id,
            'dashboard_type': dashboard.dashboard_type.value,
            'last_update': data_stream.get('last_update'),
            'data': data_stream.get('data', {}),
            'alerts': data_stream.get('alerts', []),
            'widgets': dashboard.widgets
        }
    
    def generate_dashboard_charts(self, dashboard_id: str) -> Dict[str, str]:
        """Generate interactive charts for dashboard"""
        dashboard = self.dashboards.get(dashboard_id)
        if not dashboard:
            return {'error': 'Dashboard not found'}
        
        data_stream = self.data_streams.get(dashboard_id, {})
        data = data_stream.get('data', {})
        
        charts = {}
        
        if dashboard.dashboard_type == DashboardType.EXECUTIVE:
            charts['risk_trend'] = self._generate_risk_trend_chart(data)
            charts['compliance_dashboard'] = self._generate_compliance_dashboard(data)
            charts['threat_landscape'] = self._generate_threat_landscape_chart(data)
        
        elif dashboard.dashboard_type == DashboardType.TECHNICAL:
            charts['vulnerability_distribution'] = self._generate_vulnerability_distribution_chart(data)
            charts['attack_timeline'] = self._generate_attack_timeline_chart(data)
            charts['system_health'] = self._generate_system_health_chart(data)
        
        elif dashboard.dashboard_type == DashboardType.REAL_TIME:
            charts['live_attacks'] = self._generate_live_attacks_chart(data)
            charts['network_traffic'] = self._generate_network_traffic_chart(data)
            charts['alert_feed'] = self._generate_alert_feed_chart(data)
        
        return charts
    
    def _generate_risk_trend_chart(self, data: Dict[str, Any]) -> str:
        """Generate risk trend chart"""
        # Simulate historical risk data
        dates = pd.date_range(start='2024-01-01', end=datetime.now(), freq='D')
        risk_scores = np.random.normal(5, 2, len(dates))
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=dates,
            y=risk_scores,
            mode='lines+markers',
            name='Risk Score',
            line=dict(color='red', width=2)
        ))
        
        fig.update_layout(
            title='Risk Score Trend',
            xaxis_title='Date',
            yaxis_title='Risk Score',
            template='plotly_dark'
        )
        
        return fig.to_html(include_plotlyjs=False)
    
    def _generate_compliance_dashboard(self, data: Dict[str, Any]) -> str:
        """Generate compliance dashboard chart"""
        standards = ['OWASP Top 10', 'PCI DSS', 'SOX', 'GDPR', 'ISO 27001']
        scores = [85, 92, 78, 88, 95]
        
        fig = go.Figure(data=[
            go.Bar(x=standards, y=scores, marker_color='lightblue')
        ])
        
        fig.update_layout(
            title='Compliance Scores by Standard',
            xaxis_title='Compliance Standard',
            yaxis_title='Compliance Score (%)',
            template='plotly_dark'
        )
        
        return fig.to_html(include_plotlyjs=False)
    
    def _generate_vulnerability_distribution_chart(self, data: Dict[str, Any]) -> str:
        """Generate vulnerability distribution chart"""
        vuln_types = ['SQL Injection', 'XSS', 'CSRF', 'Path Traversal', 'Command Injection']
        counts = [15, 23, 8, 12, 6]
        
        fig = go.Figure(data=[
            go.Pie(labels=vuln_types, values=counts, hole=0.3)
        ])
        
        fig.update_layout(
            title='Vulnerability Distribution',
            template='plotly_dark'
        )
        
        return fig.to_html(include_plotlyjs=False)
    
    def _generate_live_attacks_chart(self, data: Dict[str, Any]) -> str:
        """Generate live attacks chart"""
        # Simulate live attack data
        attack_types = ['Brute Force', 'SQL Injection', 'XSS', 'DDoS', 'Phishing']
        attack_counts = np.random.poisson(5, len(attack_types))
        
        fig = go.Figure(data=[
            go.Bar(x=attack_types, y=attack_counts, marker_color='red')
        ])
        
        fig.update_layout(
            title='Live Attack Monitoring',
            xaxis_title='Attack Type',
            yaxis_title='Attack Count',
            template='plotly_dark'
        )
        
        return fig.to_html(include_plotlyjs=False)

class PredictiveAnalytics:
    """Advanced predictive analytics for security"""
    
    def __init__(self):
        self.models = {}
        self.scaler = StandardScaler()
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.trend_predictor = RandomForestRegressor(n_estimators=100, random_state=42)
        self.cluster_model = KMeans(n_clusters=5, random_state=42)
        
    async def analyze_trends(self, historical_data: List[Dict[str, Any]]) -> AnalyticsResult:
        """Analyze security trends"""
        analysis_id = f"trend_analysis_{int(time.time())}"
        
        # Prepare data
        df = pd.DataFrame(historical_data)
        
        # Extract features
        features = self._extract_trend_features(df)
        
        # Perform trend analysis
        trend_results = self._perform_trend_analysis(features)
        
        # Generate predictions
        predictions = self._generate_trend_predictions(features)
        
        result = AnalyticsResult(
            analysis_id=analysis_id,
            analysis_type=AnalyticsType.TREND_ANALYSIS,
            target_data='historical_security_data',
            results={
                'trend_analysis': trend_results,
                'predictions': predictions,
                'confidence': 0.85
            },
            confidence=0.85,
            recommendations=self._generate_trend_recommendations(trend_results),
            timestamp=datetime.now()
        )
        
        return result
    
    def _extract_trend_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract features for trend analysis"""
        features = pd.DataFrame()
        
        # Time-based features
        features['day_of_week'] = pd.to_datetime(df['timestamp']).dt.dayofweek
        features['month'] = pd.to_datetime(df['timestamp']).dt.month
        features['hour'] = pd.to_datetime(df['timestamp']).dt.hour
        
        # Security features
        features['vulnerability_count'] = df.get('vulnerability_count', 0)
        features['attack_count'] = df.get('attack_count', 0)
        features['risk_score'] = df.get('risk_score', 5.0)
        features['compliance_score'] = df.get('compliance_score', 80.0)
        
        return features
    
    def _perform_trend_analysis(self, features: pd.DataFrame) -> Dict[str, Any]:
        """Perform trend analysis"""
        results = {
            'trends': {},
            'seasonality': {},
            'correlations': {}
        }
        
        # Analyze trends
        for column in features.columns:
            if features[column].dtype in ['int64', 'float64']:
                trend = np.polyfit(range(len(features)), features[column], 1)[0]
                results['trends'][column] = {
                    'direction': 'increasing' if trend > 0 else 'decreasing',
                    'slope': trend,
                    'strength': abs(trend)
                }
        
        # Analyze seasonality
        if 'day_of_week' in features.columns:
            weekly_pattern = features.groupby('day_of_week')['vulnerability_count'].mean()
            results['seasonality']['weekly'] = weekly_pattern.to_dict()
        
        # Analyze correlations
        correlation_matrix = features.corr()
        results['correlations'] = correlation_matrix.to_dict()
        
        return results
    
    def _generate_trend_predictions(self, features: pd.DataFrame) -> Dict[str, Any]:
        """Generate trend predictions"""
        # Prepare prediction data
        X = features.dropna()
        if len(X) < 10:
            return {'error': 'Insufficient data for predictions'}
        
        # Train trend predictor
        y = X['vulnerability_count']
        X_train = X.drop('vulnerability_count', axis=1)
        
        self.trend_predictor.fit(X_train, y)
        
        # Generate future predictions
        future_dates = pd.date_range(start=datetime.now(), periods=30, freq='D')
        future_features = self._generate_future_features(future_dates)
        
        predictions = self.trend_predictor.predict(future_features)
        
        return {
            'predicted_vulnerabilities': predictions.tolist(),
            'prediction_dates': future_dates.strftime('%Y-%m-%d').tolist(),
            'confidence_interval': self._calculate_confidence_interval(predictions)
        }
    
    def _generate_future_features(self, future_dates: pd.DatetimeIndex) -> pd.DataFrame:
        """Generate features for future predictions"""
        future_features = pd.DataFrame()
        future_features['day_of_week'] = future_dates.dayofweek
        future_features['month'] = future_dates.month
        future_features['hour'] = 12  # Default to noon
        
        # Add trend continuation
        future_features['vulnerability_count'] = 0  # Will be predicted
        future_features['attack_count'] = 5  # Average
        future_features['risk_score'] = 5.0  # Average
        future_features['compliance_score'] = 80.0  # Average
        
        return future_features
    
    def _calculate_confidence_interval(self, predictions: np.ndarray) -> Dict[str, float]:
        """Calculate confidence interval for predictions"""
        mean_pred = np.mean(predictions)
        std_pred = np.std(predictions)
        
        return {
            'lower_bound': mean_pred - 1.96 * std_pred,
            'upper_bound': mean_pred + 1.96 * std_pred,
            'confidence_level': 0.95
        }
    
    async def detect_anomalies(self, security_data: List[Dict[str, Any]]) -> AnalyticsResult:
        """Detect anomalies in security data"""
        analysis_id = f"anomaly_detection_{int(time.time())}"
        
        # Prepare data
        df = pd.DataFrame(security_data)
        features = self._extract_anomaly_features(df)
        
        # Detect anomalies
        anomaly_scores = self.anomaly_detector.fit_predict(features)
        anomalies = df[anomaly_scores == -1]
        
        result = AnalyticsResult(
            analysis_id=analysis_id,
            analysis_type=AnalyticsType.ANOMALY_DETECTION,
            target_data='security_data',
            results={
                'anomalies_detected': len(anomalies),
                'anomaly_details': anomalies.to_dict('records'),
                'anomaly_score': self.anomaly_detector.score_samples(features).tolist()
            },
            confidence=0.9,
            recommendations=self._generate_anomaly_recommendations(anomalies),
            timestamp=datetime.now()
        )
        
        return result
    
    def _extract_anomaly_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract features for anomaly detection"""
        features = pd.DataFrame()
        
        # Security metrics
        features['vulnerability_count'] = df.get('vulnerability_count', 0)
        features['attack_count'] = df.get('attack_count', 0)
        features['risk_score'] = df.get('risk_score', 5.0)
        features['response_time'] = df.get('response_time', 1000)
        features['error_rate'] = df.get('error_rate', 0.01)
        
        return features
    
    def _generate_trend_recommendations(self, trend_results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on trend analysis"""
        recommendations = []
        
        trends = trend_results.get('trends', {})
        
        # Check vulnerability trends
        vuln_trend = trends.get('vulnerability_count', {})
        if vuln_trend.get('direction') == 'increasing':
            recommendations.append("Implement proactive vulnerability management")
            recommendations.append("Increase security testing frequency")
        
        # Check risk score trends
        risk_trend = trends.get('risk_score', {})
        if risk_trend.get('direction') == 'increasing':
            recommendations.append("Review and update risk mitigation strategies")
            recommendations.append("Implement additional security controls")
        
        return recommendations
    
    def _generate_anomaly_recommendations(self, anomalies: pd.DataFrame) -> List[str]:
        """Generate recommendations based on anomaly detection"""
        recommendations = []
        
        if len(anomalies) > 0:
            recommendations.append("Investigate detected anomalies immediately")
            recommendations.append("Review security monitoring thresholds")
            recommendations.append("Update anomaly detection rules")
        
        return recommendations

class ComplianceAutomation:
    """Automated compliance checking and reporting"""
    
    def __init__(self):
        self.compliance_rules = self._initialize_compliance_rules()
        self.assessment_history = []
        
    def _initialize_compliance_rules(self) -> Dict[str, Dict[str, Any]]:
        """Initialize compliance rules for different standards"""
        return {
            'owasp_top_10': {
                'injection': {
                    'description': 'SQL, NoSQL, OS, and LDAP injection',
                    'severity': 'high',
                    'controls': ['input_validation', 'parameterized_queries', 'output_encoding']
                },
                'broken_authentication': {
                    'description': 'Authentication and session management flaws',
                    'severity': 'high',
                    'controls': ['multi_factor_auth', 'session_timeout', 'secure_password_policy']
                },
                'sensitive_data_exposure': {
                    'description': 'Exposure of sensitive data',
                    'severity': 'high',
                    'controls': ['encryption_at_rest', 'encryption_in_transit', 'data_classification']
                },
                'xml_external_entities': {
                    'description': 'XXE vulnerabilities',
                    'severity': 'medium',
                    'controls': ['disable_xml_external_entities', 'use_safe_xml_parsers']
                },
                'broken_access_control': {
                    'description': 'Authorization flaws',
                    'severity': 'high',
                    'controls': ['role_based_access_control', 'principle_of_least_privilege']
                },
                'security_misconfiguration': {
                    'description': 'Security configuration errors',
                    'severity': 'medium',
                    'controls': ['security_headers', 'secure_defaults', 'regular_audits']
                },
                'xss': {
                    'description': 'Cross-site scripting',
                    'severity': 'medium',
                    'controls': ['output_encoding', 'content_security_policy', 'input_validation']
                },
                'insecure_deserialization': {
                    'description': 'Insecure deserialization',
                    'severity': 'medium',
                    'controls': ['validate_serialized_data', 'use_secure_serialization']
                },
                'using_components_with_known_vulnerabilities': {
                    'description': 'Outdated or vulnerable components',
                    'severity': 'medium',
                    'controls': ['dependency_management', 'regular_updates', 'vulnerability_scanning']
                },
                'insufficient_logging_monitoring': {
                    'description': 'Inadequate logging and monitoring',
                    'severity': 'medium',
                    'controls': ['comprehensive_logging', 'real_time_monitoring', 'incident_response']
                }
            },
            'pci_dss': {
                'build_and_maintain_secure_network': {
                    'description': 'Secure network infrastructure',
                    'severity': 'high',
                    'controls': ['firewall_configuration', 'network_segmentation']
                },
                'protect_cardholder_data': {
                    'description': 'Protect stored and transmitted cardholder data',
                    'severity': 'high',
                    'controls': ['encryption', 'data_retention_policy', 'secure_transmission']
                },
                'maintain_vulnerability_management': {
                    'description': 'Vulnerability management program',
                    'severity': 'high',
                    'controls': ['regular_scanning', 'patch_management', 'secure_development']
                },
                'implement_strong_access_controls': {
                    'description': 'Access control measures',
                    'severity': 'high',
                    'controls': ['access_control_policy', 'user_authentication', 'physical_access']
                },
                'monitor_and_test_networks': {
                    'description': 'Network monitoring and testing',
                    'severity': 'high',
                    'controls': ['network_monitoring', 'penetration_testing', 'intrusion_detection']
                },
                'maintain_information_security_policy': {
                    'description': 'Information security policy',
                    'severity': 'medium',
                    'controls': ['security_policy', 'employee_training', 'incident_response_plan']
                }
            }
        }
    
    async def assess_compliance(self, target_system: str, 
                              standard: ComplianceStandard) -> ComplianceReport:
        """Assess compliance against a specific standard"""
        report_id = f"compliance_{standard.value}_{int(time.time())}"
        
        # Get compliance rules for standard
        rules = self.compliance_rules.get(standard.value, {})
        
        # Perform compliance assessment
        findings = []
        total_controls = 0
        compliant_controls = 0
        
        for rule_name, rule_details in rules.items():
            total_controls += 1
            
            # Simulate compliance check
            compliance_result = await self._check_compliance_control(rule_name, rule_details)
            
            if compliance_result['compliant']:
                compliant_controls += 1
            
            findings.append({
                'rule': rule_name,
                'description': rule_details['description'],
                'severity': rule_details['severity'],
                'compliant': compliance_result['compliant'],
                'evidence': compliance_result['evidence'],
                'recommendations': compliance_result['recommendations']
            })
        
        # Calculate compliance score
        compliance_score = (compliant_controls / total_controls) * 100 if total_controls > 0 else 0
        
        # Generate recommendations
        recommendations = self._generate_compliance_recommendations(findings)
        
        # Create compliance report
        report = ComplianceReport(
            report_id=report_id,
            standard=standard,
            assessment_date=datetime.now(),
            compliance_score=compliance_score,
            findings=findings,
            recommendations=recommendations,
            next_assessment=datetime.now() + timedelta(days=90)
        )
        
        # Store assessment history
        self.assessment_history.append(report)
        
        return report
    
    async def _check_compliance_control(self, rule_name: str, 
                                      rule_details: Dict[str, Any]) -> Dict[str, Any]:
        """Check compliance for a specific control"""
        # Simulate compliance check
        compliance_probability = 0.7  # 70% chance of being compliant
        
        is_compliant = np.random.random() < compliance_probability
        
        evidence = []
        recommendations = []
        
        if is_compliant:
            evidence.append(f"Control {rule_name} is properly implemented")
        else:
            evidence.append(f"Control {rule_name} needs improvement")
            recommendations.extend(rule_details.get('controls', []))
        
        return {
            'compliant': is_compliant,
            'evidence': evidence,
            'recommendations': recommendations
        }
    
    def _generate_compliance_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []
        
        non_compliant_findings = [f for f in findings if not f['compliant']]
        
        for finding in non_compliant_findings:
            recommendations.extend(finding.get('recommendations', []))
        
        # Add general recommendations
        if len(non_compliant_findings) > 5:
            recommendations.append("Implement comprehensive compliance management program")
            recommendations.append("Conduct regular compliance training for staff")
        
        return list(set(recommendations))  # Remove duplicates
    
    def get_compliance_trends(self, standard: ComplianceStandard, 
                            days: int = 90) -> Dict[str, Any]:
        """Get compliance trends over time"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        relevant_assessments = [
            report for report in self.assessment_history
            if report.standard == standard and report.assessment_date >= cutoff_date
        ]
        
        if not relevant_assessments:
            return {'error': 'No assessment data available'}
        
        # Calculate trends
        scores = [report.compliance_score for report in relevant_assessments]
        dates = [report.assessment_date for report in relevant_assessments]
        
        trend_analysis = {
            'average_score': np.mean(scores),
            'score_trend': 'improving' if len(scores) > 1 and scores[-1] > scores[0] else 'declining',
            'score_variance': np.var(scores),
            'assessment_count': len(relevant_assessments),
            'latest_score': scores[-1] if scores else 0
        }
        
        return trend_analysis
    
    def generate_compliance_dashboard(self, standard: ComplianceStandard) -> Dict[str, Any]:
        """Generate compliance dashboard data"""
        # Get latest assessment
        latest_assessment = None
        for report in reversed(self.assessment_history):
            if report.standard == standard:
                latest_assessment = report
                break
        
        if not latest_assessment:
            return {'error': 'No assessment data available'}
        
        # Calculate compliance metrics
        compliant_findings = [f for f in latest_assessment.findings if f['compliant']]
        non_compliant_findings = [f for f in latest_assessment.findings if not f['compliant']]
        
        severity_distribution = {}
        for finding in latest_assessment.findings:
            severity = finding['severity']
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
        
        dashboard_data = {
            'standard': standard.value,
            'compliance_score': latest_assessment.compliance_score,
            'total_findings': len(latest_assessment.findings),
            'compliant_findings': len(compliant_findings),
            'non_compliant_findings': len(non_compliant_findings),
            'severity_distribution': severity_distribution,
            'assessment_date': latest_assessment.assessment_date.isoformat(),
            'next_assessment': latest_assessment.next_assessment.isoformat(),
            'critical_findings': [f for f in non_compliant_findings if f['severity'] == 'high']
        }
        
        return dashboard_data

class AdvancedReportingAnalyticsService:
    """Main service for advanced reporting and analytics"""
    
    def __init__(self):
        self.real_time_dashboard = RealTimeDashboard()
        self.predictive_analytics = PredictiveAnalytics()
        self.compliance_automation = ComplianceAutomation()
        self.reports = []
        
    async def create_executive_dashboard(self, target_organization: str) -> Dict[str, Any]:
        """Create executive dashboard"""
        dashboard = self.real_time_dashboard.create_dashboard(DashboardType.EXECUTIVE)
        
        # Initialize dashboard with sample data
        initial_data = {
            'risk_score': 6.5,
            'vulnerability_count': 23,
            'attack_count': 5,
            'compliance_score': 85.0,
            'threat_level': 'medium',
            'system_health': 'good'
        }
        
        await self.real_time_dashboard.update_dashboard_data(dashboard.dashboard_id, initial_data)
        
        # Generate charts
        charts = self.real_time_dashboard.generate_dashboard_charts(dashboard.dashboard_id)
        
        return {
            'dashboard_id': dashboard.dashboard_id,
            'dashboard_type': dashboard.dashboard_type.value,
            'target_organization': target_organization,
            'charts': charts,
            'data': self.real_time_dashboard.get_dashboard_data(dashboard.dashboard_id)
        }
    
    async def perform_predictive_analysis(self, historical_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform comprehensive predictive analysis"""
        # Trend analysis
        trend_analysis = await self.predictive_analytics.analyze_trends(historical_data)
        
        # Anomaly detection
        anomaly_detection = await self.predictive_analytics.detect_anomalies(historical_data)
        
        # Generate predictions
        predictions = trend_analysis.results.get('predictions', {})
        
        analysis_results = {
            'trend_analysis': {
                'analysis_id': trend_analysis.analysis_id,
                'trends': trend_analysis.results.get('trend_analysis', {}),
                'recommendations': trend_analysis.recommendations,
                'confidence': trend_analysis.confidence
            },
            'anomaly_detection': {
                'analysis_id': anomaly_detection.analysis_id,
                'anomalies_detected': anomaly_detection.results.get('anomalies_detected', 0),
                'anomaly_details': anomaly_detection.results.get('anomaly_details', []),
                'recommendations': anomaly_detection.recommendations,
                'confidence': anomaly_detection.confidence
            },
            'predictions': {
                'vulnerability_forecast': predictions.get('predicted_vulnerabilities', []),
                'forecast_dates': predictions.get('prediction_dates', []),
                'confidence_interval': predictions.get('confidence_interval', {})
            }
        }
        
        return analysis_results
    
    async def assess_compliance_automation(self, target_system: str, 
                                        standards: List[ComplianceStandard]) -> Dict[str, Any]:
        """Assess compliance against multiple standards"""
        compliance_results = {}
        
        for standard in standards:
            report = await self.compliance_automation.assess_compliance(target_system, standard)
            compliance_results[standard.value] = {
                'report_id': report.report_id,
                'compliance_score': report.compliance_score,
                'assessment_date': report.assessment_date.isoformat(),
                'findings_count': len(report.findings),
                'critical_findings': len([f for f in report.findings if f['severity'] == 'high' and not f['compliant']]),
                'recommendations': report.recommendations
            }
        
        # Calculate overall compliance score
        overall_score = np.mean([result['compliance_score'] for result in compliance_results.values()])
        
        return {
            'target_system': target_system,
            'overall_compliance_score': overall_score,
            'standards_assessed': len(standards),
            'compliance_results': compliance_results,
            'summary': self._generate_compliance_summary(compliance_results)
        }
    
    def _generate_compliance_summary(self, compliance_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance summary"""
        total_findings = sum(result['findings_count'] for result in compliance_results.values())
        total_critical = sum(result['critical_findings'] for result in compliance_results.values())
        
        return {
            'total_findings': total_findings,
            'critical_findings': total_critical,
            'compliance_status': 'compliant' if total_critical == 0 else 'non_compliant',
            'priority_actions': self._identify_priority_actions(compliance_results)
        }
    
    def _identify_priority_actions(self, compliance_results: Dict[str, Any]) -> List[str]:
        """Identify priority actions from compliance results"""
        priority_actions = []
        
        for standard, result in compliance_results.items():
            if result['critical_findings'] > 0:
                priority_actions.append(f"Address {result['critical_findings']} critical findings in {standard}")
            
            if result['compliance_score'] < 80:
                priority_actions.append(f"Improve {standard} compliance score from {result['compliance_score']}%")
        
        return priority_actions
    
    def get_analytics_statistics(self) -> Dict[str, Any]:
        """Get comprehensive analytics statistics"""
        return {
            'dashboards_created': len(self.real_time_dashboard.dashboards),
            'active_alerts': len(self.real_time_dashboard.alerts),
            'compliance_assessments': len(self.compliance_automation.assessment_history),
            'predictive_models': len(self.predictive_analytics.models),
            'total_reports': len(self.reports)
        }

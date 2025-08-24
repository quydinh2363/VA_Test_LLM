"""
AI Agent for Autonomous Pentesting
Provides intelligent, autonomous security testing capabilities
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json
import random
from concurrent.futures import ThreadPoolExecutor
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import os

from app.core.config import settings
from app.security.mcp_client import MCPClient, MCPPentestOrchestrator
from app.security.exploitation_script_generator import ExploitationScriptGenerator
from app.security.burp_client import BurpClient
from app.models.security import VulnerabilityReport, ScanResult

logger = logging.getLogger(__name__)

class AgentState(Enum):
    IDLE = "idle"
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    LEARNING = "learning"

class DecisionType(Enum):
    CONTINUE_SCAN = "continue_scan"
    ESCALATE_PRIVILEGE = "escalate_privilege"
    CHAIN_EXPLOIT = "chain_exploit"
    STOP_SAFE = "stop_safe"
    ADAPT_STRATEGY = "adapt_strategy"
    REQUEST_HUMAN_INPUT = "request_human_input"

@dataclass
class AgentContext:
    target_url: str
    current_state: AgentState
    discovered_vulnerabilities: List[Dict] = field(default_factory=list)
    successful_exploits: List[Dict] = field(default_factory=list)
    failed_attempts: List[Dict] = field(default_factory=list)
    risk_score: float = 0.0
    confidence_level: float = 0.0
    session_data: Dict = field(default_factory=dict)
    learning_data: Dict = field(default_factory=dict)
    start_time: datetime = field(default_factory=datetime.now)
    last_decision: Optional[DecisionType] = None

@dataclass
class AgentDecision:
    decision_type: DecisionType
    confidence: float
    reasoning: str
    next_actions: List[str]
    risk_assessment: Dict[str, float]
    estimated_time: int
    success_probability: float

class AIModel:
    """Machine Learning model for decision making"""
    
    def __init__(self):
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.is_trained = False
        self.model_path = "models/ai_agent_model.pkl"
        self.load_model()
    
    def load_model(self):
        """Load pre-trained model if available"""
        try:
            if os.path.exists(self.model_path):
                model_data = joblib.load(self.model_path)
                self.classifier = model_data['classifier']
                self.vectorizer = model_data['vectorizer']
                self.is_trained = True
                logger.info("AI model loaded successfully")
        except Exception as e:
            logger.warning(f"Could not load AI model: {e}")
    
    def save_model(self):
        """Save trained model"""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            model_data = {
                'classifier': self.classifier,
                'vectorizer': self.vectorizer
            }
            joblib.dump(model_data, self.model_path)
            logger.info("AI model saved successfully")
        except Exception as e:
            logger.error(f"Could not save AI model: {e}")
    
    def extract_features(self, context: AgentContext) -> np.ndarray:
        """Extract features from agent context"""
        features = []
        
        # Vulnerability features
        vuln_count = len(context.discovered_vulnerabilities)
        high_severity_count = len([v for v in context.discovered_vulnerabilities 
                                 if v.get('severity', 'low') in ['high', 'critical']])
        
        # Exploit features
        success_rate = len(context.successful_exploits) / max(len(context.failed_attempts) + len(context.successful_exploits), 1)
        
        # Time features
        elapsed_time = (datetime.now() - context.start_time).total_seconds()
        
        # Risk features
        risk_score = context.risk_score
        confidence = context.confidence_level
        
        # State features
        state_encoding = {
            AgentState.IDLE: 0,
            AgentState.RECONNAISSANCE: 1,
            AgentState.VULNERABILITY_ANALYSIS: 2,
            AgentState.EXPLOITATION: 3,
            AgentState.POST_EXPLOITATION: 4,
            AgentState.REPORTING: 5,
            AgentState.LEARNING: 6
        }
        
        features = [
            vuln_count, high_severity_count, success_rate, elapsed_time,
            risk_score, confidence, state_encoding[context.current_state]
        ]
        
        return np.array(features).reshape(1, -1)
    
    def predict_decision(self, context: AgentContext) -> AgentDecision:
        """Predict next decision based on context"""
        if not self.is_trained:
            return self._default_decision(context)
        
        try:
            features = self.extract_features(context)
            prediction = self.classifier.predict(features)[0]
            probabilities = self.classifier.predict_proba(features)[0]
            
            decision_type = DecisionType(prediction)
            confidence = max(probabilities)
            
            return AgentDecision(
                decision_type=decision_type,
                confidence=confidence,
                reasoning=self._generate_reasoning(context, decision_type),
                next_actions=self._get_next_actions(decision_type),
                risk_assessment=self._assess_risks(context),
                estimated_time=self._estimate_time(decision_type),
                success_probability=self._calculate_success_probability(context, decision_type)
            )
        except Exception as e:
            logger.error(f"Error in decision prediction: {e}")
            return self._default_decision(context)
    
    def _default_decision(self, context: AgentContext) -> AgentDecision:
        """Default decision when model is not trained"""
        if context.current_state == AgentState.IDLE:
            decision_type = DecisionType.CONTINUE_SCAN
        elif context.risk_score > 0.8:
            decision_type = DecisionType.STOP_SAFE
        else:
            decision_type = DecisionType.ADAPT_STRATEGY
        
        return AgentDecision(
            decision_type=decision_type,
            confidence=0.5,
            reasoning="Using default decision logic",
            next_actions=self._get_next_actions(decision_type),
            risk_assessment=self._assess_risks(context),
            estimated_time=300,
            success_probability=0.6
        )
    
    def _generate_reasoning(self, context: AgentContext, decision: DecisionType) -> str:
        """Generate reasoning for decision"""
        reasoning_map = {
            DecisionType.CONTINUE_SCAN: f"Risk score ({context.risk_score:.2f}) is acceptable, continuing scan",
            DecisionType.ESCALATE_PRIVILEGE: "Vulnerabilities detected, attempting privilege escalation",
            DecisionType.CHAIN_EXPLOIT: "Multiple vulnerabilities found, chaining exploits for maximum impact",
            DecisionType.STOP_SAFE: f"High risk detected ({context.risk_score:.2f}), stopping for safety",
            DecisionType.ADAPT_STRATEGY: "Current approach not effective, adapting strategy",
            DecisionType.REQUEST_HUMAN_INPUT: "Complex situation detected, requesting human guidance"
        }
        return reasoning_map.get(decision, "Decision made based on current context")
    
    def _get_next_actions(self, decision: DecisionType) -> List[str]:
        """Get next actions based on decision"""
        action_map = {
            DecisionType.CONTINUE_SCAN: ["Continue vulnerability scanning", "Analyze results"],
            DecisionType.ESCALATE_PRIVILEGE: ["Attempt privilege escalation", "Search for misconfigurations"],
            DecisionType.CHAIN_EXPLOIT: ["Chain multiple exploits", "Execute post-exploitation"],
            DecisionType.STOP_SAFE: ["Stop all activities", "Generate safety report"],
            DecisionType.ADAPT_STRATEGY: ["Change scanning approach", "Try different techniques"],
            DecisionType.REQUEST_HUMAN_INPUT: ["Wait for human input", "Log current state"]
        }
        return action_map.get(decision, ["Continue current activity"])
    
    def _assess_risks(self, context: AgentContext) -> Dict[str, float]:
        """Assess various risk factors"""
        return {
            "data_breach": min(context.risk_score * 0.8, 1.0),
            "system_damage": min(context.risk_score * 0.6, 1.0),
            "detection": min(context.risk_score * 0.4, 1.0),
            "legal_issues": min(context.risk_score * 0.2, 1.0)
        }
    
    def _estimate_time(self, decision: DecisionType) -> int:
        """Estimate time for decision execution"""
        time_map = {
            DecisionType.CONTINUE_SCAN: 300,
            DecisionType.ESCALATE_PRIVILEGE: 600,
            DecisionType.CHAIN_EXPLOIT: 900,
            DecisionType.STOP_SAFE: 60,
            DecisionType.ADAPT_STRATEGY: 450,
            DecisionType.REQUEST_HUMAN_INPUT: 0
        }
        return time_map.get(decision, 300)
    
    def _calculate_success_probability(self, context: AgentContext, decision: DecisionType) -> float:
        """Calculate success probability for decision"""
        base_probability = 0.7
        
        # Adjust based on context
        if context.confidence_level > 0.8:
            base_probability += 0.2
        elif context.confidence_level < 0.3:
            base_probability -= 0.3
        
        if len(context.successful_exploits) > len(context.failed_attempts):
            base_probability += 0.1
        
        return min(max(base_probability, 0.1), 0.95)

class AutonomousPentestAgent:
    """Intelligent autonomous pentesting agent"""
    
    def __init__(self):
        self.ai_model = AIModel()
        self.mcp_client = None
        self.mcp_orchestrator = None
        self.exploitation_generator = ExploitationScriptGenerator()
        self.burp_client = BurpClient()
        
        if settings.mcp_enabled:
            self.mcp_client = MCPClient(settings.mcp_server_url, settings.mcp_api_key)
            self.mcp_orchestrator = MCPPentestOrchestrator(self.mcp_client)
        
        self.active_contexts: Dict[str, AgentContext] = {}
        self.execution_history: List[Dict] = []
        self.learning_data: List[Dict] = []
        self.is_autonomous = True
        self.safety_threshold = 0.8
        
        logger.info("Autonomous Pentest Agent initialized")
    
    async def start_autonomous_pentest(self, target_url: str, 
                                     max_duration: int = 3600,
                                     safety_level: str = "medium") -> str:
        """Start autonomous pentest session"""
        session_id = f"autonomous_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000, 9999)}"
        
        context = AgentContext(
            target_url=target_url,
            current_state=AgentState.RECONNAISSANCE
        )
        
        self.active_contexts[session_id] = context
        
        # Start autonomous execution
        asyncio.create_task(self._autonomous_execution_loop(session_id, max_duration, safety_level))
        
        logger.info(f"Started autonomous pentest session: {session_id}")
        return session_id
    
    async def _autonomous_execution_loop(self, session_id: str, max_duration: int, safety_level: str):
        """Main autonomous execution loop"""
        context = self.active_contexts[session_id]
        start_time = datetime.now()
        
        try:
            while True:
                # Check time limit
                if (datetime.now() - start_time).total_seconds() > max_duration:
                    logger.info(f"Session {session_id} reached time limit")
                    break
                
                # Get AI decision
                decision = self.ai_model.predict_decision(context)
                context.last_decision = decision.decision_type
                
                # Log decision
                self._log_decision(session_id, decision)
                
                # Execute decision
                success = await self._execute_decision(session_id, decision)
                
                # Update context
                self._update_context(context, decision, success)
                
                # Check safety conditions
                if self._should_stop_for_safety(context, safety_level):
                    logger.warning(f"Session {session_id} stopped for safety reasons")
                    break
                
                # Learning phase
                if context.current_state == AgentState.LEARNING:
                    await self._learning_phase(session_id)
                
                # State transition
                self._transition_state(context, decision)
                
                # Wait before next iteration
                await asyncio.sleep(5)
                
        except Exception as e:
            logger.error(f"Error in autonomous execution loop: {e}")
        finally:
            await self._finalize_session(session_id)
    
    async def _execute_decision(self, session_id: str, decision: AgentDecision) -> bool:
        """Execute AI decision"""
        context = self.active_contexts[session_id]
        
        try:
            if decision.decision_type == DecisionType.CONTINUE_SCAN:
                return await self._execute_scanning(context)
            
            elif decision.decision_type == DecisionType.ESCALATE_PRIVILEGE:
                return await self._execute_privilege_escalation(context)
            
            elif decision.decision_type == DecisionType.CHAIN_EXPLOIT:
                return await self._execute_chain_exploit(context)
            
            elif decision.decision_type == DecisionType.STOP_SAFE:
                return await self._execute_safe_stop(context)
            
            elif decision.decision_type == DecisionType.ADAPT_STRATEGY:
                return await self._execute_strategy_adaptation(context)
            
            elif decision.decision_type == DecisionType.REQUEST_HUMAN_INPUT:
                return await self._request_human_input(context)
            
            return False
            
        except Exception as e:
            logger.error(f"Error executing decision {decision.decision_type}: {e}")
            return False
    
    async def _execute_scanning(self, context: AgentContext) -> bool:
        """Execute vulnerability scanning"""
        try:
            # Burp Suite Pro scanning
            if self.burp_client:
                scan_result = await self.burp_client.start_scan(context.target_url)
                if scan_result:
                    vulnerabilities = await self.burp_client.get_alerts()
                    context.discovered_vulnerabilities.extend(vulnerabilities)
            
            # MCP scanning
            if self.mcp_orchestrator:
                mcp_result = await self.mcp_orchestrator.run_reconnaissance(context.target_url)
                if mcp_result.get('vulnerabilities'):
                    context.discovered_vulnerabilities.extend(mcp_result['vulnerabilities'])
            
            return True
        except Exception as e:
            logger.error(f"Error in scanning: {e}")
            return False
    
    async def _execute_privilege_escalation(self, context: AgentContext) -> bool:
        """Execute privilege escalation attempts"""
        try:
            if not self.mcp_client:
                return False
            
            # Generate privilege escalation scripts
            script_result = await self.mcp_client.generate_script({
                'target': context.target_url,
                'script_type': 'privilege_escalation',
                'context': context.session_data
            })
            
            if script_result.get('success'):
                context.successful_exploits.append({
                    'type': 'privilege_escalation',
                    'result': script_result,
                    'timestamp': datetime.now()
                })
                return True
            
            return False
        except Exception as e:
            logger.error(f"Error in privilege escalation: {e}")
            return False
    
    async def _execute_chain_exploit(self, context: AgentContext) -> bool:
        """Execute chain exploit"""
        try:
            if not self.mcp_orchestrator:
                return False
            
            # Chain multiple exploits
            chain_result = await self.mcp_orchestrator.chain_exploit(
                context.target_url,
                context.discovered_vulnerabilities
            )
            
            if chain_result.get('success'):
                context.successful_exploits.append({
                    'type': 'chain_exploit',
                    'result': chain_result,
                    'timestamp': datetime.now()
                })
                return True
            
            return False
        except Exception as e:
            logger.error(f"Error in chain exploit: {e}")
            return False
    
    async def _execute_safe_stop(self, context: AgentContext) -> bool:
        """Execute safe stop"""
        try:
            # Generate safety report
            safety_report = {
                'timestamp': datetime.now(),
                'risk_score': context.risk_score,
                'vulnerabilities_found': len(context.discovered_vulnerabilities),
                'exploits_successful': len(context.successful_exploits),
                'recommendations': self._generate_safety_recommendations(context)
            }
            
            context.session_data['safety_report'] = safety_report
            return True
        except Exception as e:
            logger.error(f"Error in safe stop: {e}")
            return False
    
    async def _execute_strategy_adaptation(self, context: AgentContext) -> bool:
        """Execute strategy adaptation"""
        try:
            # Analyze failed attempts
            failed_patterns = self._analyze_failed_patterns(context)
            
            # Adapt strategy based on patterns
            new_strategy = self._generate_adapted_strategy(failed_patterns)
            
            context.session_data['adapted_strategy'] = new_strategy
            return True
        except Exception as e:
            logger.error(f"Error in strategy adaptation: {e}")
            return False
    
    async def _request_human_input(self, context: AgentContext) -> bool:
        """Request human input"""
        try:
            # Log request for human input
            human_request = {
                'timestamp': datetime.now(),
                'reason': 'Complex situation requiring human guidance',
                'current_state': context.current_state.value,
                'risk_score': context.risk_score,
                'context_summary': self._generate_context_summary(context)
            }
            
            context.session_data['human_input_request'] = human_request
            return True
        except Exception as e:
            logger.error(f"Error requesting human input: {e}")
            return False
    
    def _update_context(self, context: AgentContext, decision: AgentDecision, success: bool):
        """Update agent context based on decision execution"""
        # Update confidence level
        if success:
            context.confidence_level = min(context.confidence_level + 0.1, 1.0)
        else:
            context.confidence_level = max(context.confidence_level - 0.1, 0.0)
        
        # Update risk score
        if decision.decision_type in [DecisionType.ESCALATE_PRIVILEGE, DecisionType.CHAIN_EXPLOIT]:
            context.risk_score = min(context.risk_score + 0.1, 1.0)
        elif decision.decision_type == DecisionType.STOP_SAFE:
            context.risk_score = max(context.risk_score - 0.2, 0.0)
    
    def _should_stop_for_safety(self, context: AgentContext, safety_level: str) -> bool:
        """Check if should stop for safety reasons"""
        safety_thresholds = {
            'low': 0.9,
            'medium': 0.8,
            'high': 0.7
        }
        
        threshold = safety_thresholds.get(safety_level, 0.8)
        return context.risk_score > threshold
    
    async def _learning_phase(self, session_id: str):
        """Execute learning phase"""
        context = self.active_contexts[session_id]
        
        # Collect learning data
        learning_entry = {
            'session_id': session_id,
            'target_url': context.target_url,
            'vulnerabilities': context.discovered_vulnerabilities,
            'exploits': context.successful_exploits,
            'failed_attempts': context.failed_attempts,
            'final_risk_score': context.risk_score,
            'success_rate': len(context.successful_exploits) / max(len(context.failed_attempts) + len(context.successful_exploits), 1),
            'timestamp': datetime.now()
        }
        
        self.learning_data.append(learning_entry)
        
        # Update AI model if enough data
        if len(self.learning_data) >= 10:
            await self._retrain_model()
    
    async def _retrain_model(self):
        """Retrain AI model with new data"""
        try:
            # Prepare training data
            X = []
            y = []
            
            for entry in self.learning_data[-50:]:  # Use last 50 entries
                context = AgentContext(
                    target_url=entry['target_url'],
                    current_state=AgentState.EXPLOITATION
                )
                context.discovered_vulnerabilities = entry['vulnerabilities']
                context.successful_exploits = entry['exploits']
                context.failed_attempts = entry['failed_attempts']
                context.risk_score = entry['final_risk_score']
                
                features = self.ai_model.extract_features(context)
                X.append(features.flatten())
                
                # Determine best decision based on success rate
                if entry['success_rate'] > 0.7:
                    y.append(DecisionType.CONTINUE_SCAN.value)
                elif entry['final_risk_score'] > 0.8:
                    y.append(DecisionType.STOP_SAFE.value)
                else:
                    y.append(DecisionType.ADAPT_STRATEGY.value)
            
            if len(X) > 5:
                X = np.array(X)
                y = np.array(y)
                
                # Retrain model
                self.ai_model.classifier.fit(X, y)
                self.ai_model.is_trained = True
                self.ai_model.save_model()
                
                logger.info("AI model retrained successfully")
        
        except Exception as e:
            logger.error(f"Error retraining model: {e}")
    
    def _transition_state(self, context: AgentContext, decision: AgentDecision):
        """Transition agent state based on decision"""
        state_transitions = {
            DecisionType.CONTINUE_SCAN: AgentState.VULNERABILITY_ANALYSIS,
            DecisionType.ESCALATE_PRIVILEGE: AgentState.EXPLOITATION,
            DecisionType.CHAIN_EXPLOIT: AgentState.POST_EXPLOITATION,
            DecisionType.STOP_SAFE: AgentState.REPORTING,
            DecisionType.ADAPT_STRATEGY: AgentState.RECONNAISSANCE,
            DecisionType.REQUEST_HUMAN_INPUT: AgentState.IDLE
        }
        
        context.current_state = state_transitions.get(decision.decision_type, context.current_state)
    
    def _log_decision(self, session_id: str, decision: AgentDecision):
        """Log AI decision"""
        log_entry = {
            'session_id': session_id,
            'timestamp': datetime.now(),
            'decision_type': decision.decision_type.value,
            'confidence': decision.confidence,
            'reasoning': decision.reasoning,
            'next_actions': decision.next_actions,
            'risk_assessment': decision.risk_assessment,
            'estimated_time': decision.estimated_time,
            'success_probability': decision.success_probability
        }
        
        self.execution_history.append(log_entry)
    
    def _analyze_failed_patterns(self, context: AgentContext) -> Dict[str, Any]:
        """Analyze patterns in failed attempts"""
        patterns = {
            'common_errors': [],
            'failed_vulnerability_types': [],
            'timing_patterns': [],
            'payload_patterns': []
        }
        
        for attempt in context.failed_attempts:
            if 'error' in attempt:
                patterns['common_errors'].append(attempt['error'])
            if 'vulnerability_type' in attempt:
                patterns['failed_vulnerability_types'].append(attempt['vulnerability_type'])
        
        return patterns
    
    def _generate_adapted_strategy(self, failed_patterns: Dict[str, Any]) -> Dict[str, Any]:
        """Generate adapted strategy based on failed patterns"""
        strategy = {
            'approach': 'adaptive',
            'techniques': [],
            'timing_adjustments': {},
            'payload_modifications': {}
        }
        
        # Adapt based on common errors
        if 'timeout' in failed_patterns['common_errors']:
            strategy['timing_adjustments']['timeout'] = 'increased'
        
        if 'authentication' in failed_patterns['common_errors']:
            strategy['techniques'].append('bypass_authentication')
        
        return strategy
    
    def _generate_safety_recommendations(self, context: AgentContext) -> List[str]:
        """Generate safety recommendations"""
        recommendations = []
        
        if context.risk_score > 0.8:
            recommendations.append("Immediate system isolation recommended")
            recommendations.append("Review all discovered vulnerabilities")
            recommendations.append("Implement emergency patches")
        
        if len(context.successful_exploits) > 0:
            recommendations.append("Review successful exploit paths")
            recommendations.append("Implement additional security controls")
        
        return recommendations
    
    def _generate_context_summary(self, context: AgentContext) -> str:
        """Generate context summary for human input"""
        return f"""
        Target: {context.target_url}
        Current State: {context.current_state.value}
        Risk Score: {context.risk_score:.2f}
        Vulnerabilities Found: {len(context.discovered_vulnerabilities)}
        Successful Exploits: {len(context.successful_exploits)}
        Failed Attempts: {len(context.failed_attempts)}
        Confidence Level: {context.confidence_level:.2f}
        """
    
    async def _finalize_session(self, session_id: str):
        """Finalize pentest session"""
        context = self.active_contexts[session_id]
        
        # Generate final report
        final_report = {
            'session_id': session_id,
            'target_url': context.target_url,
            'start_time': context.start_time,
            'end_time': datetime.now(),
            'duration': (datetime.now() - context.start_time).total_seconds(),
            'final_state': context.current_state.value,
            'vulnerabilities_discovered': len(context.discovered_vulnerabilities),
            'successful_exploits': len(context.successful_exploits),
            'final_risk_score': context.risk_score,
            'ai_decisions_made': len([h for h in self.execution_history if h['session_id'] == session_id]),
            'session_data': context.session_data
        }
        
        context.session_data['final_report'] = final_report
        
        # Remove from active contexts
        if session_id in self.active_contexts:
            del self.active_contexts[session_id]
        
        logger.info(f"Session {session_id} finalized")
    
    def get_session_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get status of active session"""
        if session_id not in self.active_contexts:
            return None
        
        context = self.active_contexts[session_id]
        return {
            'session_id': session_id,
            'target_url': context.target_url,
            'current_state': context.current_state.value,
            'risk_score': context.risk_score,
            'confidence_level': context.confidence_level,
            'vulnerabilities_found': len(context.discovered_vulnerabilities),
            'successful_exploits': len(context.successful_exploits),
            'last_decision': context.last_decision.value if context.last_decision else None,
            'start_time': context.start_time,
            'elapsed_time': (datetime.now() - context.start_time).total_seconds()
        }
    
    def get_all_sessions(self) -> List[Dict[str, Any]]:
        """Get all active sessions"""
        return [self.get_session_status(session_id) for session_id in self.active_contexts.keys()]
    
    def get_execution_history(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get execution history"""
        if session_id:
            return [h for h in self.execution_history if h['session_id'] == session_id]
        return self.execution_history
    
    def set_autonomous_mode(self, enabled: bool):
        """Set autonomous mode"""
        self.is_autonomous = enabled
        logger.info(f"Autonomous mode {'enabled' if enabled else 'disabled'}")
    
    def set_safety_threshold(self, threshold: float):
        """Set safety threshold"""
        self.safety_threshold = max(0.0, min(1.0, threshold))
        logger.info(f"Safety threshold set to {self.safety_threshold}")

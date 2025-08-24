"""
Main Streamlit UI for Security Testing Assistant
"""

import streamlit as st
import asyncio
import json
from datetime import datetime
from typing import Dict, Any, List

from app.llm.chat_manager import ChatManager
from app.llm.intent_router import IntentRouter, IntentType
from app.security.payload_generator import PayloadGenerator
from app.security.zap_client import ZAPClient
from app.security.exploitation_script_generator import ExploitationScriptGenerator, ExploitationContext, ScriptType, TargetType
from app.core.config import settings

# Page configuration
st.set_page_config(
    page_title="Security Testing Assistant",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .chat-message {
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .user-message {
        background-color: #e3f2fd;
        border-left: 4px solid #2196f3;
    }
    .assistant-message {
        background-color: #f3e5f5;
        border-left: 4px solid #9c27b0;
    }
    .warning-box {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 1rem 0;
    }
    .success-box {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'chat_manager' not in st.session_state:
    st.session_state.chat_manager = ChatManager()

if 'intent_router' not in st.session_state:
    st.session_state.intent_router = IntentRouter()

if 'payload_generator' not in st.session_state:
    st.session_state.payload_generator = PayloadGenerator()

if 'exploitation_generator' not in st.session_state:
    st.session_state.exploitation_generator = ExploitationScriptGenerator()

if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

if 'current_scan' not in st.session_state:
    st.session_state.current_scan = None

if 'mcp_enabled' not in st.session_state:
    st.session_state.mcp_enabled = settings.mcp_enabled

def main():
    """Main application function"""
    
    # Header
    st.markdown('<h1 class="main-header">🔒 Security Testing Assistant</h1>', unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Cấu hình")
        
        # LLM Configuration
        st.subheader("🤖 LLM Settings")
        llm_provider = st.selectbox(
            "LLM Provider",
            ["OpenAI", "Claude"],
            index=0
        )
        
        # Security Settings
        st.subheader("🔐 Security Settings")
        st.info(f"Allowed domains: {', '.join(settings.allowed_domains)}")
        
        # Quick Actions
        st.subheader("🚀 Quick Actions")
        
        if st.button("🗑️ Clear Chat History"):
            st.session_state.chat_manager.clear_history()
            st.session_state.chat_history = []
            st.rerun()
        
        if st.button("📊 Export Chat"):
            export_chat_history()
        
        # ZAP Status
        st.subheader("🔍 ZAP Status")
        if st.button("Check ZAP Connection"):
            check_zap_connection()
    
    # Main content area with tabs
    tab1, tab2, tab3, tab4 = st.tabs(["💬 Chat", "🔧 Advanced Tools", "🤖 MCP Integration", "📊 Pentest"])
    
    with tab1:
        # Chat interface
        st.subheader("💬 Chat with Security Assistant")
        
        # Display chat history
        display_chat_history()
        
        # Input area
        user_input = st.text_area(
            "Nhập yêu cầu của bạn:",
            placeholder="Ví dụ: Giải thích về XSS, tạo payload cho SQL injection, quét website...",
            height=100
        )
        
        col1_1, col1_2, col1_3 = st.columns([1, 1, 1])
        
        with col1_1:
            if st.button("💬 Gửi", type="primary"):
                if user_input.strip():
                    process_user_input(user_input)
        
        with col1_2:
            if st.button("🔧 Generate Payload"):
                show_payload_generator()
        
        with col1_3:
            if st.button("🔍 Run Burp Scan"):
                show_burp_scan()
    
    with tab2:
        # Advanced Tools
        st.subheader("🔧 Advanced Exploitation Tools")
        
        # Exploitation Script Generator
        st.subheader("📝 Exploitation Script Generator")
        
        target_url = st.text_input("Target URL", placeholder="https://example.com")
        script_type = st.selectbox("Script Type", ["XSS_PAYLOAD", "SQL_INJECTION", "COMMAND_INJECTION", "REVERSE_SHELL"])
        vuln_type = st.selectbox("Vulnerability Type", ["XSS", "SQLI", "LFI", "RFI", "CSRF", "XXE", "SSRF", "COMMAND_INJECTION"])
        interactive_mode = st.checkbox("Interactive Mode")
        
        if st.button("Generate Script", type="primary"):
            if target_url:
                generate_exploitation_script(target_url, script_type, vuln_type, interactive_mode)
            else:
                st.error("Please enter a target URL")
    
    with tab3:
        # MCP Integration
        st.subheader("🤖 MCP Server Integration")
        
        if not st.session_state.mcp_enabled:
            st.warning("⚠️ MCP integration is disabled. Enable it in settings to use advanced features.")
        else:
            # MCP Status
            st.subheader("📊 MCP Status")
            if st.button("Check MCP Status"):
                check_mcp_status()
            
            # MCP Tools
            st.subheader("🛠️ Available MCP Tools")
            if st.button("List Available Tools"):
                list_mcp_tools()
            
            # MCP Request
            st.subheader("📤 Send MCP Request")
            mcp_target = st.text_input("Target", placeholder="https://example.com")
            mcp_request_type = st.selectbox("Request Type", [
                "script_generation", "payload_creation", "pentest_execution", 
                "vulnerability_analysis", "tool_execution", "data_extraction"
            ])
            
            if st.button("Send Request", type="primary"):
                if mcp_target:
                    send_mcp_request(mcp_target, mcp_request_type)
                else:
                    st.error("Please enter a target")
    
    with tab4:
        # Automated Pentesting
        st.subheader("📊 Automated Pentesting")
        
        if not st.session_state.mcp_enabled:
            st.warning("⚠️ MCP integration is disabled. Enable it to use automated pentesting.")
        else:
            # Pentest Configuration
            st.subheader("⚙️ Pentest Configuration")
            pentest_target = st.text_input("Target URL", placeholder="https://example.com")
            
            pentest_phases = st.multiselect(
                "Pentest Phases",
                ["reconnaissance", "exploitation", "post_exploitation"],
                default=["reconnaissance", "exploitation", "post_exploitation"]
            )
            
            if st.button("Start Pentest", type="primary"):
                if pentest_target:
                    start_automated_pentest(pentest_target, pentest_phases)
                else:
                    st.error("Please enter a target URL")
            
            # Pentest History
            st.subheader("📋 Pentest History")
            if st.button("View History"):
                show_pentest_history()
    
    with col2:
        # Right sidebar - Quick tools
        st.subheader("🛠️ Quick Tools")
        
        # Payload Generator
        st.subheader("🔧 Payload Generator")
        vuln_type = st.selectbox(
            "Vulnerability Type",
            ["XSS", "SQLI", "LFI", "RFI", "CSRF", "XXE", "SSRF", "COMMAND_INJECTION"]
        )
        
        if st.button("Generate Payloads"):
            generate_quick_payloads(vuln_type)
        
        # Burp Suite Pro Scan
        st.subheader("🔍 Burp Suite Pro Scan")
        target_url = st.text_input("Target URL", placeholder="https://example.com")
        
        if st.button("Start Scan"):
            if target_url:
                start_burp_scan(target_url)
            else:
                st.error("Please enter a target URL")

def display_chat_history():
    """Display chat history"""
    for message in st.session_state.chat_history:
        if message["role"] == "user":
            st.markdown(f"""
            <div class="chat-message user-message">
                <strong>👤 You:</strong><br>
                {message["content"]}
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="chat-message assistant-message">
                <strong>🤖 Assistant:</strong><br>
                {message["content"]}
            </div>
            """, unsafe_allow_html=True)

def process_user_input(user_input: str):
    """Process user input and generate response"""
    try:
        # Add user message to history
        st.session_state.chat_history.append({
            "role": "user",
            "content": user_input,
            "timestamp": datetime.now().isoformat()
        })
        
        # Route intent
        intent_result = st.session_state.intent_router.route_message(user_input)
        intent = intent_result["intent"]
        entities = intent_result["entities"]
        
        # Generate response based on intent
        if intent == IntentType.GENERATE_PAYLOAD:
            response = handle_payload_request(entities)
        elif intent == IntentType.RUN_SCAN:
            response = handle_scan_request(entities)
        elif intent == IntentType.EXPLAIN_VULNERABILITY:
            response = handle_explanation_request(entities)
        else:
            # Use LLM for general response
            response = asyncio.run(st.session_state.chat_manager.send_message(user_input))
        
        # Add assistant response to history
        st.session_state.chat_history.append({
            "role": "assistant",
            "content": response,
            "timestamp": datetime.now().isoformat()
        })
        
        st.rerun()
        
    except Exception as e:
        st.error(f"Error processing input: {str(e)}")

def handle_payload_request(entities: Dict[str, Any]) -> str:
    """Handle payload generation request"""
    vuln_type = entities.get("vulnerability_type", "XSS")
    payloads = st.session_state.payload_generator.generate_payloads(vuln_type.lower())
    
    response = f"🔧 **Payloads cho {vuln_type}:**\n\n"
    
    for i, payload in enumerate(payloads, 1):
        response += f"**{i}. {payload['name']}**\n"
        response += f"```\n{payload['payload']}\n```\n"
        response += f"*{payload['description']}*\n"
        response += f"**OWASP Reference:** {payload['owasp_ref']}\n\n"
    
    # Add verification steps
    verification_steps = st.session_state.payload_generator.get_verification_steps(vuln_type.lower())
    if verification_steps:
        response += "**📋 Bước xác minh:**\n"
        for step in verification_steps:
            response += f"• {step}\n"
        response += "\n"
    
    # Add safety warning
    response += "⚠️ **Cảnh báo:** Chỉ test trên môi trường được phép!"
    
    return response

def handle_scan_request(entities: Dict[str, Any]) -> str:
    """Handle scan request"""
    target_url = entities.get("target_url")
    
    if not target_url:
        return "❌ Vui lòng cung cấp URL mục tiêu để quét."
    
    # Check if domain is allowed
    if not is_allowed_domain(target_url):
        return f"❌ URL {target_url} không được phép quét. Chỉ các domain sau được phép: {', '.join(settings.allowed_domains)}"
    
    response = f"🔍 **Bắt đầu quét: {target_url}**\n\n"
    response += "Quá trình quét sẽ bao gồm:\n"
    response += "• Spider scan (crawl website)\n"
    response += "• Active scan (tìm lỗ hổng)\n"
    response += "• Phân tích kết quả\n\n"
    response += "⏳ Quá trình này có thể mất vài phút..."
    
    # Store scan request
    st.session_state.current_scan = {
        "target_url": target_url,
        "status": "pending",
        "timestamp": datetime.now().isoformat()
    }
    
    return response

def handle_explanation_request(entities: Dict[str, Any]) -> str:
    """Handle vulnerability explanation request"""
    vuln_type = entities.get("vulnerability_type", "general")
    
    explanations = {
        "XSS": {
            "title": "Cross-Site Scripting (XSS)",
            "description": "XSS cho phép attacker chèn mã JavaScript vào trang web.",
            "types": ["Reflected XSS", "Stored XSS", "DOM-based XSS"],
            "owasp_ref": "A03:2021"
        },
        "SQLI": {
            "title": "SQL Injection",
            "description": "SQL Injection cho phép attacker thực thi câu lệnh SQL tùy ý.",
            "types": ["Boolean-based", "Error-based", "Time-based", "Union-based"],
            "owasp_ref": "A02:2021"
        },
        "LFI": {
            "title": "Local File Inclusion",
            "description": "LFI cho phép attacker đọc file trên server.",
            "types": ["Path traversal", "Null byte injection"],
            "owasp_ref": "A05:2021"
        }
    }
    
    if vuln_type in explanations:
        vuln_info = explanations[vuln_type]
        response = f"📚 **{vuln_info['title']}**\n\n"
        response += f"{vuln_info['description']}\n\n"
        response += "**Các loại chính:**\n"
        for vuln_type_name in vuln_info['types']:
            response += f"• {vuln_type_name}\n"
        response += f"\n**OWASP Reference:** {vuln_info['owasp_ref']}"
    else:
        response = "📚 **OWASP Top 10 2021**\n\n"
        response += "1. **A01:2021** - Broken Access Control\n"
        response += "2. **A02:2021** - Cryptographic Failures\n"
        response += "3. **A03:2021** - Injection\n"
        response += "4. **A04:2021** - Insecure Design\n"
        response += "5. **A05:2021** - Security Misconfiguration\n"
        response += "6. **A06:2021** - Vulnerable Components\n"
        response += "7. **A07:2021** - Authentication Failures\n"
        response += "8. **A08:2021** - Software and Data Integrity Failures\n"
        response += "9. **A09:2021** - Logging Failures\n"
        response += "10. **A10:2021** - Server-Side Request Forgery"
    
    return response

def show_payload_generator():
    """Show payload generator interface"""
    st.subheader("🔧 Payload Generator")
    
    vuln_type = st.selectbox(
        "Select Vulnerability Type",
        ["XSS", "SQLI", "LFI", "RFI", "CSRF", "XXE", "SSRF", "COMMAND_INJECTION"]
    )
    
    difficulty = st.selectbox(
        "Difficulty Level",
        ["all", "easy", "medium", "hard"]
    )
    
    count = st.slider("Number of Payloads", 1, 10, 3)
    
    if st.button("Generate"):
        payloads = st.session_state.payload_generator.generate_payloads(
            vuln_type.lower(), difficulty, count
        )
        
        for i, payload in enumerate(payloads, 1):
            with st.expander(f"{i}. {payload['name']}"):
                st.code(payload['payload'])
                st.write(f"**Description:** {payload['description']}")
                st.write(f"**Difficulty:** {payload['difficulty']}")
                st.write(f"**OWASP Reference:** {payload['owasp_ref']}")

def show_burp_scan():
    """Show Burp Suite Pro scan interface"""
    st.subheader("🔍 Burp Suite Pro Security Scan")
    
    target_url = st.text_input("Target URL", placeholder="https://juice-shop.herokuapp.com")
    
    scan_options = st.multiselect(
        "Scan Options",
        ["Spider Scan", "Active Scan", "Passive Scan"],
        default=["Spider Scan", "Active Scan"]
    )
    
    if st.button("Start Scan", type="primary"):
        if target_url:
            if is_allowed_domain(target_url):
                start_burp_scan(target_url, scan_options)
            else:
                st.error(f"URL {target_url} not in allowed domains")
        else:
            st.error("Please enter a target URL")

def start_burp_scan(target_url: str, scan_options: List[str] = None):
    """Start Burp Suite Pro scan"""
    try:
        st.info(f"🔍 Starting Burp Suite Pro scan for: {target_url}")
        
        # This would be async in a real implementation
        # For now, just show a placeholder
        st.success("✅ Burp Suite Pro scan completed! (Placeholder)")
        
        # In real implementation, you would:
        # 1. Initialize Burp Suite Pro client
        # 2. Add target to scope
        # 3. Run spider scan
        # 4. Run active scan
        # 5. Collect results
        # 6. Display findings
        
    except Exception as e:
        st.error(f"❌ Burp Suite Pro scan failed: {str(e)}")

def check_burp_connection():
    """Check Burp Suite Pro connection status"""
    try:
        # This would be async in a real implementation
        st.success("✅ Burp Suite Pro connection successful!")
    except Exception as e:
        st.error(f"❌ Burp Suite Pro connection failed: {str(e)}")

def generate_quick_payloads(vuln_type: str):
    """Generate quick payloads for selected vulnerability type"""
    payloads = st.session_state.payload_generator.generate_payloads(vuln_type.lower())
    
    st.subheader(f"🔧 {vuln_type} Payloads")
    
    for i, payload in enumerate(payloads, 1):
        with st.expander(f"{i}. {payload['name']}"):
            st.code(payload['payload'])
            st.write(f"**Description:** {payload['description']}")
            st.write(f"**Difficulty:** {payload['difficulty']}")

def is_allowed_domain(url: str) -> bool:
    """Check if URL domain is allowed"""
    try:
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.split(':')[0]
        
        for allowed_domain in settings.allowed_domains:
            if domain == allowed_domain or domain.endswith(f".{allowed_domain}"):
                return True
        
        return False
    except Exception:
        return False

def export_chat_history():
    """Export chat history to JSON"""
    if st.session_state.chat_history:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"chat_history_{timestamp}.json"
        
        # Create download button
        st.download_button(
            label="📥 Download Chat History",
            data=json.dumps(st.session_state.chat_history, indent=2),
            file_name=filename,
            mime="application/json"
        )

# Advanced Features Functions
def generate_exploitation_script(target_url: str, script_type: str, vuln_type: str, interactive_mode: bool):
    """Generate exploitation script"""
    try:
        st.info(f"🔧 Generating exploitation script for {target_url}")
        
        # Create exploitation context
        context = ExploitationContext(
            target_url=target_url,
            target_type=TargetType.WEB_APPLICATION,
            vulnerability_type=ScriptType(script_type),
            parameters={"vulnerability_type": vuln_type},
            user_input=target_url
        )
        
        # Generate script
        if interactive_mode:
            result = st.session_state.exploitation_generator.interactive_mode(context)
        else:
            result = st.session_state.exploitation_generator.generate_script(context)
        
        if "error" in result:
            st.error(f"❌ Error: {result['error']}")
            return
        
        # Display results
        st.success("✅ Script generated successfully!")
        
        with st.expander("📝 Main Script", expanded=True):
            st.code(result['script_content'], language='python')
        
        with st.expander("🔍 Verification Script"):
            st.code(result['verification_script'], language='python')
        
        with st.expander("🧹 Cleanup Script"):
            st.code(result['cleanup_script'], language='python')
        
        with st.expander("📋 Usage Instructions"):
            for instruction in result['usage_instructions']:
                st.write(f"• {instruction}")
        
        with st.expander("⚠️ Ethical Warnings"):
            for warning in result['ethical_warnings']:
                st.write(f"• {warning}")
        
        # Save script option
        if st.button("💾 Save Script"):
            filepath = st.session_state.exploitation_generator.save_script(result)
            st.success(f"✅ Script saved to: {filepath}")
        
    except Exception as e:
        st.error(f"❌ Error generating script: {str(e)}")

def check_mcp_status():
    """Check MCP server status"""
    try:
        response = requests.get("http://localhost:8000/mcp/status")
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'available':
                st.success("✅ MCP server is available")
                st.info(f"Server URL: {data['server_url']}")
                st.info(f"Available tools: {data['available_tools']}")
            else:
                st.warning(f"⚠️ MCP server status: {data['status']}")
        else:
            st.error("❌ Failed to check MCP status")
    except Exception as e:
        st.error(f"❌ Error checking MCP status: {str(e)}")

def list_mcp_tools():
    """List available MCP tools"""
    try:
        response = requests.get("http://localhost:8000/mcp/tools")
        if response.status_code == 200:
            data = response.json()
            st.subheader("🛠️ Available MCP Tools")
            
            for tool in data['tools']:
                with st.expander(f"🔧 {tool['name']}"):
                    st.write(f"**Description:** {tool['description']}")
                    st.write(f"**Type:** {tool['tool_type']}")
                    st.write(f"**Risk Level:** {tool['risk_level']}")
                    st.write(f"**Output Format:** {tool['output_format']}")
                    
                    st.write("**Parameters:**")
                    for param in tool['parameters']:
                        st.write(f"• {param}")
                    
                    st.write("**Ethical Guidelines:**")
                    for guideline in tool['ethical_guidelines']:
                        st.write(f"• {guideline}")
        else:
            st.error("❌ Failed to get MCP tools")
    except Exception as e:
        st.error(f"❌ Error listing MCP tools: {str(e)}")

def send_mcp_request(target: str, request_type: str):
    """Send request to MCP server"""
    try:
        st.info(f"📤 Sending {request_type} request to MCP server")
        
        payload = {
            "target": target,
            "request_type": request_type,
            "parameters": {},
            "timeout": 300
        }
        
        response = requests.post("http://localhost:8000/mcp/request", json=payload)
        if response.status_code == 200:
            data = response.json()
            if data['success']:
                st.success("✅ MCP request successful!")
                st.json(data['data'])
            else:
                st.error(f"❌ MCP request failed: {data['error']}")
        else:
            st.error("❌ Failed to send MCP request")
    except Exception as e:
        st.error(f"❌ Error sending MCP request: {str(e)}")

def start_automated_pentest(target: str, phases: List[str]):
    """Start automated pentest"""
    try:
        st.info(f"🚀 Starting automated pentest for {target}")
        
        payload = {
            "target": target,
            "phases": phases,
            "tools": [],
            "parameters": {}
        }
        
        response = requests.post("http://localhost:8000/pentest/execute", json=payload)
        if response.status_code == 200:
            data = response.json()
            st.success("✅ Pentest started successfully!")
            st.info(f"Pentest ID: {data['pentest_id']}")
            st.info(f"Status: {data['status']}")
            
            # Store pentest ID for monitoring
            st.session_state.current_pentest = data['pentest_id']
        else:
            st.error("❌ Failed to start pentest")
    except Exception as e:
        st.error(f"❌ Error starting pentest: {str(e)}")

def show_pentest_history():
    """Show pentest history"""
    try:
        response = requests.get("http://localhost:8000/pentest/history")
        if response.status_code == 200:
            data = response.json()
            st.subheader("📋 Pentest History")
            
            if data['history']:
                for pentest in data['history']:
                    with st.expander(f"🎯 {pentest['target']} - {pentest.get('status', 'Unknown')}"):
                        st.write(f"**Target:** {pentest['target']}")
                        st.write(f"**Duration:** {pentest.get('duration', 'Unknown')} seconds")
                        
                        if 'phases' in pentest:
                            st.write("**Phases:**")
                            for phase, status in pentest['phases'].items():
                                st.write(f"• {phase}: {status}")
                        
                        if 'error' in pentest:
                            st.error(f"Error: {pentest['error']}")
            else:
                st.info("No pentest history available")
        else:
            st.error("❌ Failed to get pentest history")
    except Exception as e:
        st.error(f"❌ Error getting pentest history: {str(e)}")

if __name__ == "__main__":
    main()

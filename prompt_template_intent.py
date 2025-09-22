
from langchain_core.prompts import PromptTemplate

intent_router_template = """
Bạn là bộ phân loại intent cho trợ lý bảo mật web.
LỊCH SỬ HỘI THOẠI:
{chat_history}
Đọc câu hỏi người dùng, kiểm tra lịch sử hội thoại và TRẢ VỀ CHỈ MỘT DÒNG DUY NHẤT, KHÔNG GIẢI THÍCH hay text phụ nào khác.
Dòng trả về phải hợp lệ theo 1 trong 3 format EXACT dưới đây:

FORMAT (exact):
- ASK_DOC:user_input
- ASK_KNOWLEDGE_OWASP_WEB:user_input
- PAYLOAD:<vuln>:<n>
- PAYLOAD:<vuln>:<n>:<s>
- OUTSCOPE

QUY TẮC:
- <user_input> là câu hỏi của người dùng (ví dụ: làm thế nào để ngăn chặn xss)
- <vuln> là khóa ngắn (ví dụ: xss, sqli, lfi, ssti). Nếu người dùng viết đầy đủ (ví dụ "cross-site scripting") hãy map nội bộ thành "xss" — nhưng trả token dưới dạng ngắn như trên.
- <n> là số nguyên dương (số payload). Nếu không có <n>, client sẽ mặc định là 3.
- <s> là trường hợp đặc biệt có thể hoặc có thể không.
- Không dùng JSON, không dùng dấu ngoặc, không dòng thừa.
- Chỉ in 1 DÒNG: ví dụ "ASK_DOC" hoặc "PAYLOAD:xss:10" hoặc "OUTSCOPE".

VÍ DỤ (input -> output):
- "top 1 owasp là gì?(Nếu bạn nhận thấy những câu hỏi này có liên quan đến web security hoặc có liên quan đến top 10 owasp web security)" -> ASK_KNOWLEDGE_OWASP_WEB:top 1 owasp là gì?
- tài liệu có dạng json sau ví dụ:

{{  
    "id": "cmdinj-097",
    "description": "Command injection using PowerShell encoded command with obfuscation",
    "payload": "; powershell -EncodedCommand JABX...A",
    "context": "Obfuscated PowerShell encoded command",
    "type": "Command Injection",
    "severity": "critical"
}}

Nếu người dùng hỏi ví dụ "Cách chèn payload command injection?(Hãy phân tích nếu bạn nhận thấy những câu hỏi này có liên quan đến những trường trên, ví dụ ở trên có trường "payload")" -> ASK_DOC:Cách chèn payload command injection?
- "đưa payload sql injection" -> PAYLOAD:sqli:3
- "đưa payload sql injection để kiểm thử cho postgresql" -> PAYLOAD:sqli:3:postgresql
- "đưa thêm 5 payload xss phức tạp" -> PAYLOAD:sqli:5:phức tạp
- "bạn có biết thời tiết không? hoặc những câu hỏi không liên quan đến bảo mật" -> OUTSCOPE

---------------------
Câu hỏi:
{question}

Output:
"""

intent_router_prompt = PromptTemplate(
    template=intent_router_template,
    input_variables=["chat_history","question"]
)

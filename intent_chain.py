# intent_chain.py
from langchain.chains import LLMChain
from langchain_groq import ChatGroq
from prompt_template_intent import intent_router_prompt  
from dotenv import load_dotenv

load_dotenv()

llm = ChatGroq(
    model="openai/gpt-oss-120b",
    temperature=0
)

# Tạo LLMChain cho intent routing
intent_chain = LLMChain(
    llm=llm,
    prompt=intent_router_prompt,
    output_key="token"  
)

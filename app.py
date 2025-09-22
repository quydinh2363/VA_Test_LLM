import json, os, time
from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma
from langchain.docstore.document import Document
from langchain_groq import ChatGroq
from langchain.chains import RetrievalQA
from langchain_huggingface import HuggingFaceEmbeddings
from langchain.memory import ConversationBufferMemory
from dotenv import load_dotenv
from langchain.chains import LLMChain
import json
from htmlTemplates import css, bot_template, user_template
import streamlit as st
from prompt_template_LLM import security_prompt_llm
from intent_chain import intent_chain
from db import *


with open("WEB_APPLICATION_PAYLOADS.jsonl", "r", encoding="utf-8") as f:
    text = f.read()

# Loại bỏ BOM hoặc ký tự vô hình (như U+00a0, U+feff)
text = text.replace("\u00a0", "").replace("\ufeff", "")

data = json.loads(text) 

# --- 2. Chuyển từng entry thành Document ---
docs = []
for entry in data:
    content = f"""
ID: {entry.get('id', '')}
Description: {entry.get('description', '')}
Payload: {entry.get('payload', '')}
Context: {entry.get('context', '')}
Type: {entry.get('type', '')}
Severity: {entry.get('severity', '')}
"""
    docs.append(
        Document(
            page_content=content,
            metadata={
                "id": entry.get("id", ""),
                "severity": entry.get("severity", ""),
                "type": entry.get("type", "")
            }
        )
    )

# ========== 3. Tạo embeddings + index ==========
persist_dir = "./chroma_db"
embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

# nếu index đã tồn tại thì load, nếu chưa thì tạo mới
if os.path.exists(persist_dir):
    vectorstore = Chroma(persist_directory=persist_dir, embedding_function=embeddings)
else:
    vectorstore = Chroma.from_documents(docs, embeddings, persist_directory=persist_dir)

load_dotenv()
llm = ChatGroq(model="openai/gpt-oss-120b", temperature=0)


# ========== 5. Retrieval QA ==========
retriever = vectorstore.as_retriever(search_kwargs={"k": 3})

memory = ConversationBufferMemory(
    memory_key="chat_history",
    output_key="result",
    return_messages=True
)

qa = RetrievalQA.from_chain_type(
    llm=llm,
    retriever=retriever,
    chain_type="stuff",
    memory = memory,
    chain_type_kwargs={"prompt": security_prompt_llm},
    return_source_documents=True
)



def handle_userinput(user_question):
    intent_result = intent_chain.invoke({"question": user_question})
    raw_token = intent_result["token"].splitlines()[0].strip()
    print(raw_token)
    response = st.session_state.conversation.invoke({"query": raw_token})

    st.session_state.chat_history.append({"role": "user", "content": user_question})
    st.session_state.chat_history.append({"role": "assistant", "content": response["result"]})

    for message in reversed(st.session_state.chat_history):
        if message["role"] == "user":
            st.write(user_template.replace("{{MSG}}", message["content"]), unsafe_allow_html=True)
        else:
            st.write(bot_template.replace("{{MSG}}", message["content"]), unsafe_allow_html=True)

def main():
    st.set_page_config(page_title="Security QA", page_icon="🛡️")
    st.write(css, unsafe_allow_html=True)
    init_db()

    col1, col2 = st.columns([1, 3])

    # --- Cột trái: Danh sách chat ---
    with col1:
        st.header("Chats")
        conversations = get_conversations()

        # Nút tạo cuộc trò chuyện mới
        if st.button("➕ New Chat"):
            conv_id, title = create_conversation()
            st.session_state.current_conv = conv_id
            st.rerun()

        # Danh sách các cuộc trò chuyện
        for cid, title in conversations:
            c1, c2 = st.columns([4, 1])
            if c1.button(title, key=f"conv_{cid}"):
                st.session_state.current_conv = cid
                st.rerun()

            # Nút xoá chat
            if c2.button("🗑", key=f"del_{cid}"):
                delete_conversation(cid)
                if "current_conv" in st.session_state and st.session_state.current_conv == cid:
                    del st.session_state.current_conv
                st.rerun()

    # --- Cột phải: Chat window ---
    with col2:
        st.header("Chat Window")

        if "conversation" not in st.session_state:
            st.session_state.conversation = qa  # dùng lại RetrievalQA bạn tạo

        if "current_conv" not in st.session_state:
            st.info("Chọn hoặc tạo một cuộc hội thoại bên trái")
            return

        conv_id = st.session_state.current_conv
        messages = get_messages(conv_id)
        
        if prompt := st.chat_input("Đặt câu hỏi hoặc yêu cầu về bảo mật web security:"):
            intent_result = intent_chain.invoke({"question": prompt})
            raw_token = intent_result["token"].strip()
            print("Câu trả lời của intent router: ", raw_token)
            response = st.session_state.conversation.invoke({"query": raw_token})

            save_message(conv_id, "user", prompt)
            save_message(conv_id, "assistant", response["result"])

            st.rerun()
        # Hiển thị lịch sử
        for msg in messages:
            if msg["role"] == "user":
                st.write(user_template.replace("{{MSG}}", msg["content"]), unsafe_allow_html=True)
            else:
                st.write(bot_template.replace("{{MSG}}", msg["content"]), unsafe_allow_html=True)

        # Input chat
        

        

    # if "conversation" not in st.session_state:
    #     st.session_state.conversation = qa
    # if "chat_history" not in st.session_state:
    #     st.session_state.chat_history = []

    # user_question = st.text_input("Đặt câu hỏi hoặc yêu cầu của bạn về bảo mật web security:")
    # if user_question:
    #     handle_userinput(user_question)
    # if st.button("please click me!"):
    #     progress_bar = st.progress(0)
    #     for percent in range(101):
    #         time.sleep(0.05)
    #         progress_bar.progress(percent)
    #     st.balloons()

if __name__ == "__main__":
    main()
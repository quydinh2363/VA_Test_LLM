from dotenv import load_dotenv
import streamlit as st
import os
from PyPDF2 import PdfReader
from langchain.text_splitter import CharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_groq import ChatGroq
from langchain.memory import ConversationBufferMemory
from langchain.chains import ConversationalRetrievalChain
from htmlTemplates import css, bot_template, user_template
from langchain.llms import huggingface_hub
from langchain.prompts import PromptTemplate
from langchain.chains.combine_documents.stuff import StuffDocumentsChain
from langchain.chains import LLMChain




def get_pdf_text(pdf_docs):
    text = ""
    for pdf in pdf_docs:
        pdf_reader = PdfReader(pdf)
        for page in pdf_reader.pages:
            text += page.extract_text()
    return text

def get_text_chunks(raw_text):
    text_splitter = CharacterTextSplitter(
        separator="\n",
        chunk_size=1000,
        chunk_overlap=200,
        length_function=len
    )
    chunks = text_splitter.split_text(raw_text)
    return chunks

def get_vectorstore(text_chunks):
    embeddings = HuggingFaceEmbeddings(model_name="BAAI/bge-large-en")
    vectorstore = FAISS.from_texts(texts=text_chunks, embedding=embeddings)
    return vectorstore

def get_conversation_chain(vectorstore):
    llm = ChatGroq(model="openai/gpt-oss-20b", api_key=os.getenv("GROQ_API_KEY"))
    # llm = huggingface_hub.HuggingFaceHub(repo_id="google/flan-t5-xxl", model_kwargs={"temperature":0.5, "max_length":512}, huggingfacehub_api_token=os.getenv("HUGGINGFACEHUB_API_TOKEN"))
    prompt_template = """
    Bạn là một trợ lý ảo chuyên phân tích bảo mật. 
    Bạn nhận tài liệu và phải vừa:
    1. Giải thích nội dung trong tài liệu.
    2. Dựa trên các ví dụ trong tài liệu, hãy **tự suy luận và sáng tạo thêm** những ví dụ mới có cùng ý nghĩa hoặc cùng mục đích (nhưng KHÔNG được bịa ra thứ sai lệch với ngữ cảnh).

    Nguyên tắc:
    - Nếu trong tài liệu có payload, hãy phân tích mẫu payload đó và tạo ra thêm 2–3 payload mới cùng loại (biến thể).
    - Nếu tài liệu không có ví dụ rõ ràng, hãy trả lời: "Xin lỗi, tôi không tìm thấy ví dụ trong tài liệu."
    - Khi tạo ra nội dung mới, hãy giải thích ngắn gọn bạn đã biến đổi như thế nào.
    ----------------
    {context}
    ----------------
    Câu hỏi: {question}
    """

    PROMPT = PromptTemplate(
        template=prompt_template,
        input_variables=["context", "question"]
    )
    # doc_chain = StuffDocumentsChain(
    #     llm_chain=LLMChain(llm=llm, prompt=PROMPT),
    #     document_variable_name="context"
    # )
    memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)
    conversation_chain = ConversationalRetrievalChain.from_llm(
        llm=llm,
        retriever=vectorstore.as_retriever(),
        combine_docs_chain_kwargs={"prompt": PROMPT},
        memory=memory
    )
    return conversation_chain
    
def handle_userinput(user_question):
    response = st.session_state.conversation({"question": user_question})
    st.session_state.chat_history = response["chat_history"]
    for i, message in enumerate(st.session_state.chat_history):
        if i % 2 == 0:
            st.write(user_template.replace("{{MSG}}", message.content), unsafe_allow_html=True)
        else:
            st.write(bot_template.replace("{{MSG}}", message.content), unsafe_allow_html=True)

def main():
    load_dotenv()
    st.set_page_config(page_title="My virtual Assistant App", page_icon="🤖")
    st.write(css, unsafe_allow_html=True)
    if "conversation" not in st.session_state:
        st.session_state.conversation = None
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = None
    st.header("Welcome to My virtual Assistant App! 🤖")
    user_question = st.text_input("Ask me anything:")
    if user_question:
        handle_userinput(user_question)
    st.write(user_template.replace("{{MSG}}", "hello bot"), unsafe_allow_html=True)
    st.write(bot_template.replace("{{MSG}}", "hello my friend"), unsafe_allow_html=True)
    with st.sidebar:
        st.subheader("Your documents here")
        pdf_docs = st.file_uploader(
            "Upload your documents here and click on Process", accept_multiple_files=True)
        if st.button("Process"):
            with st.spinner("Processing..."):
                # get pdf text
                raw_text = get_pdf_text(pdf_docs)
                
                # get the text chunks
                chunks = get_text_chunks(raw_text)
                # st.write(chunks)

                # create vector store
                vectorstore = get_vectorstore(chunks)

                # create conversation chain
                st.session_state.conversation = get_conversation_chain(vectorstore)



if __name__ == "__main__":
    main()
from langchain_groq import ChatGroq
from langchain.chains import RetrievalQA
from langchain_community.document_loaders import WebBaseLoader
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
import os
from dotenv import load_dotenv

load_dotenv()


api_key = os.getenv("GROQ_API_KEY")

loader = WebBaseLoader("https://owasp.org/Top10/")
docs = loader.load()


embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
db = Chroma.from_documents(docs, embeddings)

# Dùng Groq làm LLM
llm = ChatGroq(model="openai/gpt-oss-20b",api_key=api_key)

qa = RetrievalQA.from_chain_type(llm=llm, retriever=db.as_retriever())

print(qa.run("""
hãy đưa ra 5 payload để kiểm tra SQL Injection."""))
import sqlite3

DB_PATH = "chat.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Tạo bảng conversations
    c.execute("""
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT
        )
    """)

    # Tạo bảng messages (có liên kết với conversation_id)
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER,
            role TEXT,
            content TEXT,
            FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
        )
    """)

    conn.commit()
    conn.close()

def get_conversations():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, title FROM conversations ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def create_conversation():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Đếm số chat hiện có
    c.execute("SELECT COUNT(*) FROM conversations")
    count = c.fetchone()[0]
    
    # Tạo tên mới theo số thứ tự
    title = f"Chat {count + 1}"
    
    # Insert vào DB
    c.execute("INSERT INTO conversations (title) VALUES (?)", (title,))
    conversation_id = c.lastrowid
    
    conn.commit()
    conn.close()
    
    return conversation_id, title

def delete_conversation(conversation_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Xoá tin nhắn thuộc conversation trước
    c.execute("DELETE FROM messages WHERE conversation_id=?", (conversation_id,))
    # Xoá conversation
    c.execute("DELETE FROM conversations WHERE id=?", (conversation_id,))

    conn.commit()
    conn.close()

def get_messages(conversation_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT role, content FROM messages WHERE conversation_id=? ORDER BY id", (conversation_id,))
    rows = c.fetchall()
    conn.close()
    return [{"role": r, "content": c} for r, c in rows]

def save_message(conversation_id, role, content):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO messages (conversation_id, role, content) VALUES (?, ?, ?)", (conversation_id, role, content))
    conn.commit()
    conn.close()

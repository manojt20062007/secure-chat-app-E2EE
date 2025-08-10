# server.py

from flask import Flask, request, jsonify
import sqlite3
import os
from datetime import datetime, timezone

app = Flask(__name__)

DB_FILE = "chat.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Create users table
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        public_key TEXT NOT NULL
    )
    """)

    # Create messages table
    c.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        receiver TEXT NOT NULL,
        message TEXT NOT NULL, -- Base64 encrypted
        timestamp TEXT NOT NULL,
        sender_public_key TEXT NOT NULL, -- sender's pubkey at send time
        receiver_public_key TEXT NOT NULL -- receiver's pubkey at send time
    )
    """)

    conn.commit()
    conn.close()

# ✅ Ensure DB is initialized even when using Gunicorn/Render
init_db()

@app.route('/')
def home():
    return "✅ Secure Chat Server (E2EE + DB + Key-versioning) Running"

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    public_key = data.get("public_key")

    if not username or not password or not public_key:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, public_key) VALUES (?, ?, ?)",
                  (username, password, public_key))
        conn.commit()
        return jsonify({"status": "success", "message": "Signup successful"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Username already exists"}), 409
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()

    if result and result[0] == password:
        return jsonify({"status": "success", "message": "Login successful"})
    else:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

@app.route('/get_key', methods=['GET'])
def get_key():
    username = request.args.get("username")
    if not username:
        return jsonify({"status": "error", "message": "Username required"}), 400

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()

    if result:
        return jsonify({"status": "success", "public_key": result[0]})
    else:
        return jsonify({"status": "error", "message": "User not found"}), 404

@app.route('/send', methods=['POST'])
def send_message():
    data = request.json
    sender = data.get("sender")
    receiver = data.get("receiver")
    encrypted_msg = data.get("message") # Base64 ciphertext
    sender_pub = data.get("sender_public_key") # required

    if not sender or not receiver or not encrypted_msg or not sender_pub:
        return jsonify({"status": "error", "message": "Missing data"}), 400

    # fetch receiver's current public key from users table (store snapshot)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username = ?", (receiver,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "Receiver not found"}), 404

    receiver_pub = row[0]
    timestamp = datetime.now(timezone.utc).isoformat()

    c.execute("""
    INSERT INTO messages
    (sender, receiver, message, timestamp, sender_public_key, receiver_public_key)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (sender, receiver, encrypted_msg, timestamp, sender_pub, receiver_pub))

    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "Message stored"})

@app.route('/messages', methods=['GET'])
def get_messages():
    user1 = request.args.get("user1")
    user2 = request.args.get("user2")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    SELECT sender, receiver, message, timestamp, sender_public_key, receiver_public_key
    FROM messages
    WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
    ORDER BY id ASC
    """, (user1, user2, user2, user1))
    rows = c.fetchall()
    conn.close()

    messages = []
    for row in rows:
        messages.append({
            "sender": row[0],
            "receiver": row[1],
            "message": row[2],
            "timestamp": row[3],
            "sender_public_key": row[4],
            "receiver_public_key": row[5]
        })

    return jsonify({"status": "success", "messages": messages})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)

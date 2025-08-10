# client.py
import requests
import base64
import os
from crypto_utils import generate_key_pair, derive_shared_key, encrypt_message, decrypt_message

BASE_URL = "http://127.0.0.1:8080"
PRIVATE_KEY_FILE = "private_key.bin"
PUBLIC_KEY_FILE = "public_key.bin"

username = ""
private_key_bytes = None
public_key_bytes = None

def save_keys(priv_b, pub_b):
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(priv_b)
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(pub_b)

def load_keys():
    global private_key_bytes, public_key_bytes
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key_bytes = f.read()
    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key_bytes = f.read()

def signup():
    global username, private_key_bytes, public_key_bytes
    print("=== Sign Up ===")
    username = input("Enter new username: ")
    password = input("Enter password: ")
    priv_b, pub_b = generate_key_pair()
    private_key_bytes = priv_b
    public_key_bytes = pub_b
    save_keys(priv_b, pub_b)
    pub_b64 = base64.b64encode(pub_b).decode()
    res = requests.post(f"{BASE_URL}/signup", json={
        "username": username, "password": password, "public_key": pub_b64
    })
    print(res.json())

def login():
    global username
    print("=== Login ===")
    username = input("Enter username: ")
    password = input("Enter password: ")
    res = requests.post(f"{BASE_URL}/login", json={"username": username, "password": password})
    print(res.json())

def get_remote_pub(username_remote):
    res = requests.get(f"{BASE_URL}/get_key", params={"username": username_remote})
    data = res.json()
    if data.get("status") != "success":
        print("Error getting key:", data)
        return None
    return base64.b64decode(data["public_key"])

def send_message():
    receiver = input("To: ")
    plaintext = input("Message: ")
    # fetch receiver's current pubkey to encrypt for them
    receiver_pub = get_remote_pub(receiver)
    if not receiver_pub:
        return
    shared = derive_shared_key(private_key_bytes, receiver_pub)
    encrypted_b64 = encrypt_message(shared, plaintext)
    sender_pub_b64 = base64.b64encode(public_key_bytes).decode()
    res = requests.post(f"{BASE_URL}/send", json={
        "sender": username,
        "receiver": receiver,
        "message": encrypted_b64,
        "sender_public_key": sender_pub_b64
    })
    print("✅ Sent" if res.status_code == 200 else "❌ Failed")

def fetch_messages():
    chat_with = input("Chat with: ")
    res = requests.get(f"{BASE_URL}/messages", params={"user1": username, "user2": chat_with})
    data = res.json()
    if data.get("status") != "success":
        print("Error fetching:", data)
        return
    for msg in data["messages"]:
        sender = msg["sender"]
        encrypted_b64 = msg["message"]
        timestamp = msg.get("timestamp", "")
        sender_pub_b64 = msg.get("sender_public_key")
        receiver_pub_b64 = msg.get("receiver_public_key")

        try:
            if sender == username:
                # I sent it -> use my private key + receiver_public_key stored with message
                if not receiver_pub_b64:
                    raise Exception("missing receiver pubkey on message")
                receiver_pub = base64.b64decode(receiver_pub_b64)
                shared = derive_shared_key(private_key_bytes, receiver_pub)
            else:
                # I received it -> use my private key + sender_public_key stored with message
                if not sender_pub_b64:
                    raise Exception("missing sender pubkey on message")
                sender_pub = base64.b64decode(sender_pub_b64)
                shared = derive_shared_key(private_key_bytes, sender_pub)

            plaintext = decrypt_message(shared, encrypted_b64)
        except Exception as e:
            plaintext = f"[Decryption Failed: {e}]"

        print(f"[{timestamp}] {sender}: {plaintext}")

def main():
    global private_key_bytes, public_key_bytes, username
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        choice = input("Load existing keys (y) or generate new keys (n)? ").strip().lower()
        if choice == "y":
            load_keys()
            print("Keys loaded.")
            if input("Login (y/n)? ").strip().lower() == "y":
                login()
        else:
            signup()
    else:
        signup()

    while True:
        print("\n1. Send Message\n2. View Messages\n3. Exit")
        c = input("Choose: ").strip()
        if c == "1":
            send_message()
        elif c == "2":
            fetch_messages()
        elif c == "3":
            break

if __name__ == "__main__":
    main()

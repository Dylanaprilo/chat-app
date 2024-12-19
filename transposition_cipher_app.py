import streamlit as st
import mysql.connector
import bcrypt

# Database Configuration
def init_db():
    conn = mysql.connector.connect(
        host="localhost",
        user="root", 
        password="", 
        database="chat_app_db" 
    )
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        password VARCHAR(255) NOT NULL
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        sender INT NOT NULL,
                        receive INT NOT NULL,
                        encrypted_message TEXT NOT NULL,
                        encryption_key VARCHAR(50) NOT NULL,
                        FOREIGN KEY (sender) REFERENCES users(id) ON DELETE CASCADE,
                        FOREIGN KEY (receiver) REFERENCES users(id) ON DELETE CASCADE
                    )''')

    conn.commit()
    conn.close()

# Encryption and Decryption Functions
def encrypt_transposition_cipher(plaintext, key):
    key = int(key)
    n = len(plaintext)
    columns = ['' for _ in range(key)]
    for i, char in enumerate(plaintext):
        columns[i % key] += char
    return ''.join(columns)

def decrypt_transposition_cipher(ciphertext, key):
    key = int(key)
    n = len(ciphertext)
    rows = n // key
    extra = n % key
    cols = ['' for _ in range(key)]
    idx = 0

    for i in range(key):
        length = rows + (1 if i < extra else 0)
        cols[i] = ciphertext[idx:idx + length]
        idx += length

    plaintext = ''
    for i in range(rows + 1):
        for col in cols:
            if i < len(col):
                plaintext += col[i]
    return plaintext

# User Authentication
def login(username, password):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="chat_app_db"
    )
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user[0].encode('utf-8')):
        return True
    return False

def register(username, password):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="chat_app_db"
    )
    cursor = conn.cursor()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
        conn.commit()
        conn.close()
        return True
    except mysql.connector.IntegrityError:
        conn.close()
        return False

# Messaging Functions
def send_message(sender_username, receiver_username, encrypted_message, encryption_key):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="chat_app_db"
    )
    cursor = conn.cursor()

    # Get sender and receiver IDs
    cursor.execute("SELECT id FROM users WHERE username=%s", (sender_username,))
    sender_id = cursor.fetchone()
    cursor.execute("SELECT id FROM users WHERE username=%s", (receiver_username,))
    receiver_id = cursor.fetchone()

    if not sender_id or not receiver_id:
        conn.close()
        raise ValueError("Sender or Receiver does not exist in the database")

    # Insert the message
    cursor.execute(
        "INSERT INTO messages (sender, receiver, encrypted_message, encryption_key) VALUES (%s, %s, %s, %s)", 
        (sender_id[0], receiver_id[0], encrypted_message, encryption_key)
    )
    conn.commit()
    conn.close()


def get_messages(receiver_username):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="chat_app_db"
    )
    cursor = conn.cursor()

    # Get receiver ID
    cursor.execute("SELECT id FROM users WHERE username=%s", (receiver_username,))
    receiver_id = cursor.fetchone()

    if not receiver_id:
        conn.close()
        raise ValueError("Receiver does not exist in the database")

    # Retrieve messages with sender's username
    cursor.execute('''
        SELECT users.username, messages.encrypted_message, messages.encryption_key 
        FROM messages 
        JOIN users ON messages.sender = users.id 
        WHERE messages.receiver = %s
    ''', (receiver_id[0],))
    
    messages = cursor.fetchall()
    conn.close()
    return messages

# Initialize Database
init_db()

# Streamlit App
st.title("Secure Chat Application")

# Authentication
st.sidebar.title("Login / Register")
option = st.sidebar.radio("Choose an option", ["Login", "Register"])

if option == "Login":
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Login"):
        if login(username, password):
            st.session_state['username'] = username
            st.success(f"Welcome {username}!")
        else:
            st.error("Invalid username or password")

if option == "Register":
    username = st.sidebar.text_input("New Username")
    password = st.sidebar.text_input("New Password", type="password")
    if st.sidebar.button("Register"):
        if register(username, password):
            st.success("Registration successful! Please login.")
        else:
            st.error("Username already exists.")

if 'username' in st.session_state:
    st.sidebar.title(f"Logged in as {st.session_state['username']}")
    st.sidebar.write("---")

    # Chat Section
    st.header("Chat")
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="chat_app_db"
    )
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username != %s", (st.session_state['username'],))
    users = [row[0] for row in cursor.fetchall()]
    conn.close()

    if users:
        selected_user = st.selectbox("Select a user to chat with", users)
        st.subheader(f"Chat with {selected_user}")

        # Sending Message
        message = st.text_area("Enter your message:")
        key = st.text_input("Enter encryption key (integer):")
        if st.button("Send"):
            if message and key.isdigit():
                encrypted_message = encrypt_transposition_cipher(message, key)
                try:
                    send_message(st.session_state['username'], selected_user, encrypted_message, key)
                    st.success("Message sent!")
                except ValueError as e:
                    st.error(str(e))
        else:
            st.error("Please enter a valid message and key.")

        # Receiving Messages
        st.subheader("Incoming Messages")
        messages = get_messages(st.session_state['username'])
        for index, (sender_username, encrypted_message, encryption_key) in enumerate(messages):
            st.write(f"From: {sender_username}")
            st.write(f"Encrypted Message: {encrypted_message}")
            st.write(f"Key: {encryption_key}")
            
            # Use index to make the key unique
            if st.button(f"Decrypt message from {sender_username}", key=f"decrypt_{sender_username}_{index}"):
                decrypted_message = decrypt_transposition_cipher(encrypted_message, encryption_key)
                st.success(f"Decrypted Message: {decrypted_message}")
    else:
        st.write("No other users available for chat.")

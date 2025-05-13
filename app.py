import streamlit as st
import hashlib       # built-in python library for making the data in hashing format
from cryptography.fernet import Fernet          # Fernet is a class of cryptography (a popular security library) that provides secure AES Encryption and decryption
import base64      # for encoding/decoding data for storage
import os     # allows to interact with operating system
import json        # helps to read and write .json file

# ------- Data File Path -------------
DATA_FILE = "data.json"

# ---- Functions --------
def generate_key():
    return Fernet.generate_key()

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def get_fernet(passkey):
    key = hashlib.sha256(passkey.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))

def encrypt_data(data, passkey):
    f = get_fernet(passkey)
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, passkey):
    f = get_fernet(passkey)
    return f.decrypt(encrypted_data.encode()).decode()

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {"users": {}, "stored_data": {}}

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump({"users": users, "stored_data": stored_data}, f)

loaded = load_data()
stored_data = loaded["stored_data"]
users = loaded["users"]
if "login_status" not in st.session_state:
    st.session_state.login_status = {"logged_in": False, "username": ""}
if "attempts" not in st.session_state:
    st.session_state.attempts = {}
if "page" not in st.session_state:
    st.session_state.page = "Login"


# ----- Streamlit Pages -------
def login_page():
    st.markdown("""
        <div style="text-align: center;">
            <h1>🔐 Secure Data System</h1>
            <h4>Welcome! Please login or signup to continue.</h4>
        </div>
        """, unsafe_allow_html=True)
    auth_choice = st.radio("Select an option", ["Login", "Signup"], horizontal=True)

    if auth_choice == "Login":
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            hashed_password = hash_passkey(password)
            if username in users and users[username] == hashed_password:
                st.session_state.login_status["logged_in"] = True
                st.session_state.login_status["username"] = username
                st.session_state.attempts[username] = 0
                st.success("✅ Login successful !!")
                st.session_state.page = "Home"
                st.rerun()
            else:
                st.error("❌ Invalid credentials")

    elif auth_choice == "Signup":
        username = st.text_input("New Username")
        password = st.text_input("New Password", type="password")

        if st.button("Signup"):
            if username in users:
                st.warning("⚠️ Username already exists!")
            else:
                users[username] = hash_passkey(password)
                stored_data[username] = {}
                st.session_state.attempts[username] = 0
                save_data()
                st.success("✅ Account created. Please login.")

def sidebar():
    with st.sidebar:
        st.markdown(f"""
            <div style="padding: 10px 0 20px 0;">
                <p style="font-size: 18px; font-weight: 700;">👋 Welcome, {st.session_state.login_status['username']} </p>
            </div>
            <hr style='margin-top: 0;'>
        """, unsafe_allow_html=True)
        

        st.markdown("### 🧰 Choose a Tool:")
        menu = st.radio("Navigation menu", ["🏠 Dashboard", "📥 Store Data", "🔐 Retrieve Data", "🚪 Logout"], label_visibility="collapsed")

        st.markdown("<hr style='margin-top: 30px;'>", unsafe_allow_html=True)
        st.markdown(
            "<p style='font-size: 13px; color: grey;'>💡 Your data is safe and encrypted!</p>",
            unsafe_allow_html=True
        )

        return menu

    
def home_page():
    menu = sidebar()

    if menu == "🏠 Dashboard":
        st.markdown(f"""
            <div style='text-align: center; padding: 20px 0;'>
                <h1>🏠 Welcome, {st.session_state.login_status['username']}!</h1>
                <h4>Secure Data Encryption System</h4>
            </div>

            ### 🔧 Features :
            - 📝 **Signup & 🔓 Login** for secure access
            - 📥 **Store** & 🔐 **Retrieve** encrypted content using a personal passkey
            - 💾 **Secure storage** in a local JSON file
            - ✅ **Logout/Login anytime** to manage access
            - 🧠 **Brute-force protection** to block repeated wrong passkey attempts

            ---

            ### 🛠️ Tools & Technologies Used:
            - 🐍 Python
            - 🖥️ Streamlit
            - 🔐 Cryptography
            - 📄 JSON for secure data storage
            - 🔑 Simple hashed authentication
            """, unsafe_allow_html=True)

    elif menu == "📥 Store Data":
        insert_data_page()

    elif menu == "🔐 Retrieve Data":
        retrieve_data_page()

    elif menu == "🚪 Logout":
        logout_confirmation()

def insert_data_page():
    st.header("🔒 Add & Encrypt Your Private Data")
    st.markdown("""
        ### How to use:
        - 📝 Enter your secret data in the text area below
        - 🔑 Choose a secure passkey (you'll need it to access your data later)
        - 📌 Remember your passkey, it&apos;s the only way to retrieve your data!
        - 💾 Click "Store Securely" to save your encrypted data
    """, unsafe_allow_html=True)
    
    
    st.markdown(f"""
        <div style="font-size:18px; font-weight:700; margin-bottom: 10px; margin-top: 20px;">
        📝 <span>Enter the secret message you want to encrypt</span>
        </div>
        """, unsafe_allow_html=True)

    text = st.text_area("Secret Data", label_visibility="collapsed")

    st.markdown(f"""
        <div style="font-size:18px; font-weight:700; margin-bottom: 10px; margin-top: 20px;">
        🔐 <span>Choose a strong passkey to secure your secret</span>
        </div>
        """, unsafe_allow_html=True)
    passkey = st.text_input("Passkey", type="password", label_visibility="collapsed")


    if st.button("Store Securely"):
        if passkey:
            # generate the encryption key using Fernet
            encryption_key = generate_key() # store the encryption key
            fernet = Fernet(encryption_key)
            encrypted = fernet.encrypt(text.encode()).decode() # Encrypts the data
            hashed_passkey = hash_passkey(passkey)

            # Append the encrypted data and key to the users data list
            if "encrypted_data" not in stored_data[st.session_state.login_status["username"]]:
                stored_data[st.session_state.login_status["username"]]["encrypted_data"] = []

            stored_data[st.session_state.login_status["username"]]["encrypted_data"].append({
                "encrypted_text": encrypted,
                "encryption_key": encryption_key.decode(),
                "passkey": hashed_passkey
            })

            save_data()
            st.success("✅ Data stored securely!")
        else:
            st.warning("⚠️ Passkey required")

def retrieve_data_page():
    st.header("📥 Retrieve Your Encrypted Data")
    st.markdown("""
        ### How to Use : 
        - 🔍 Review Entries: You'll see a list of your encrypted data entries.
        - 📑 Identify an Entry: Each entry is labeled as **Entry #** for reference.
        - 🔑 Enter Your Passkey: Type in the passkey you used when saving this specific entry.
        - 🗝️ Click 'Decrypt': If the passkey matches, your secret message will be revealed.
        - 🔄 Repeat As Needed: You can decrypt multiple entries individually.
                
        <p style="font-size: 16px; color: #d9534f;"><b>⚠️ &nbsp; Note:</b> If you enter the wrong passkey, the data will not be decrypted.</p>
    """, unsafe_allow_html=True)

    user = st.session_state.login_status["username"]

    # retrieve and display all encrypted data entries
    encrypted_data_list = stored_data[user].get("encrypted_data", [])
    for idx, data in enumerate(encrypted_data_list):
        encrypted_text = data.get("encrypted_text")
        encryption_key = data.get("encryption_key")
        passkey =  data.get("passkey")


        # User passkey for the specific passkey to decrypt 
        st.markdown(f"""
            <div style="font-size:18px; font-weight:700; margin-bottom: 10px; margin-top: 20px;">
                🔑 Enter your passkey to decrypt Entry #{idx + 1}
            </div>
        """, unsafe_allow_html=True)

        passkey_input = st.text_input("Password", key=f"passkey_input_{idx}", type="password",  label_visibility="collapsed" )

        if passkey_input and st.button(f"Decrypt Entry #{idx + 1}"):
            if hash_passkey(passkey_input) == passkey:
                fernet = Fernet(encryption_key.encode())
                decrypted_message = fernet.decrypt(encrypted_text.encode()).decode()
                st.success(f"✅ Decrypted Message #{idx + 1}:")
                st.code(decrypted_message)
            else:
                st.error(f"❌ Incorrect passkey for Entry #{idx + 1}.")

def logout_confirmation():
    st.markdown("""
        <div style="text-align: center; padding: 20px;">
            <h2>🚪 Confirm Logout</h2>
            <p style="font-size: 16px; color: #555;">
                Are you sure you want to log out of your session?<br>
                You'll need to log in again to access your secure data.
            </p>
        </div>
    """, unsafe_allow_html=True)

    confirm_logout = st.radio("🔒 Please confirm:", ["No, keep me logged in", "Yes, log me out"], index=0)

    if confirm_logout == "Yes, log me out":
        st.success("✅ You have been logged out successfully.")
        st.session_state.login_status = {"logged_in": False, "username": ""}
        st.session_state.page = "Login"
        st.rerun()
    elif confirm_logout == "No, keep me logged in":
        st.info("🔁 Staying logged in.")
        st.session_state.page = "Home"
        st.rerun()


if st.session_state.page == "Login":
    login_page()
elif st.session_state.page == "Home":
    if st.session_state.login_status["logged_in"]:
        home_page()
    else:
        st.warning("⚠️ Please log in to access this page.")
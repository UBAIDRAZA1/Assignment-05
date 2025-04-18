import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64

# Custom CSS for styling
st.markdown("""
<style>
    /* Main container */
    .main {
        background-color: #f8f9fa;
    }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(135deg, #2c3e50, #4ca1af);
        color: white;
    }
    
    /* Sidebar title */
    [data-testid="stSidebar"] .sidebar-title {
        color: white !important;
        font-size: 24px !important;
        font-weight: 600 !important;
    }
    
    /* Button styling */
    .stButton>button {
        background: linear-gradient(45deg, #4CAF50, #2E7D32);
        color: white;
        border-radius: 8px;
        padding: 10px 24px;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .stButton>button:hover {
        transform: scale(1.05);
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }
    
    /* Input field styling */
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        border-radius: 8px;
        padding: 10px;
    }
    
    /* Card styling */
    .card {
        background: white;
        border-radius: 10px;
        padding: 20px;
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        margin-bottom: 20px;
    }
    
    /* Footer styling */
    .footer {
        position: fixed;
        left: 0;
        bottom: 0;
        width: 100%;
        background-color: #2c3e50;
        color: white;
        text-align: center;
        padding: 10px;
        font-size: 12px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state variables
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0

# Utility functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, data_id):
    try:
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]["passkey"] == hashed_passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except Exception:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

def generate_data_id():
    import uuid
    return str(uuid.uuid4())

def reset_failed_attempts():
    st.session_state.failed_attempts = 0

def change_page(page):
    st.session_state.current_page = page

# Main App UI
st.title("🔒 Secure Vault")
st.markdown("---")

# Sidebar with creator credit
with st.sidebar:
    st.title("🔐 Navigation")
    st.markdown("---")
    menu = ["Home", "Store Data", "Retrieve Data", "Login"]
    choice = st.selectbox("", menu, index=menu.index(st.session_state.current_page), label_visibility="collapsed")
    st.session_state.current_page = choice
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; margin-top: 50px;">
        <p>Created by</p>
        <h3>Ubaid Raza</h3>
    </div>
    """, unsafe_allow_html=True)

# Security check
if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = "Login"
    st.warning("🔒 Too many failed attempts! Reauthorization required.")

# Page content
if st.session_state.current_page == "Home":
    st.subheader("🏠 Welcome to Secure Vault")
    st.markdown("""
    <div class="card">
        <h4>Store and retrieve sensitive data securely</h4>
        <p>This system uses military-grade encryption to protect your information.</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📂 Store New Data", use_container_width=True):
            change_page("Store Data")
    with col2:
        if st.button("🔍 Retrieve Data", use_container_width=True):
            change_page("Retrieve Data")
    
    st.info(f"🔢 Currently storing {len(st.session_state.stored_data)} encrypted data entries")

elif st.session_state.current_page == "Store Data":
    st.subheader("📂 Store Data Securely")
    with st.form("store_form"):
        st.markdown("""
        <div class="card">
            <p>Enter your sensitive data below. It will be encrypted before storage.</p>
        </div>
        """, unsafe_allow_html=True)
        
        user_data = st.text_area("Your Data:", height=150)
        passkey = st.text_input("Encryption Passkey:", type="password")
        confirm_passkey = st.text_input("Confirm Passkey:", type="password")
        
        if st.form_submit_button("🔒 Encrypt & Save"):
            if user_data and passkey and confirm_passkey:
                if passkey != confirm_passkey:
                    st.error("⚠️ Passkeys do not match!")
                else:
                    data_id = generate_data_id()
                    hashed_passkey = hash_passkey(passkey)
                    encrypted_text = encrypt_data(user_data, passkey)
                    
                    st.session_state.stored_data[data_id] = {
                        "encrypted_text": encrypted_text,
                        "passkey": hashed_passkey
                    }
                    
                    st.success("✅ Data stored securely!")
                    st.balloons()
                    
                    st.markdown("""
                    <div class="card">
                        <h4>🔑 Your Data ID</h4>
                        <p>Save this ID to retrieve your data later:</p>
                        <code>{}</code>
                        <p class="small">⚠️ Without this ID and passkey, your data cannot be recovered</p>
                    </div>
                    """.format(data_id), unsafe_allow_html=True)
            else:
                st.error("⚠️ All fields are required!")

elif st.session_state.current_page == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    
    attempts_remaining = 3 - st.session_state.failed_attempts
    st.warning(f"⚠️ Attempts remaining: {attempts_remaining}")
    
    with st.form("retrieve_form"):
        data_id = st.text_input("Enter Data ID:")
        passkey = st.text_input("Enter Passkey:", type="password")
        
        if st.form_submit_button("🔓 Decrypt Data"):
            if data_id and passkey:
                if data_id in st.session_state.stored_data:
                    encrypted_text = st.session_state.stored_data[data_id]["encrypted_text"]
                    decrypted_text = decrypt_data(encrypted_text, passkey, data_id)

                    if decrypted_text:
                        st.success("✅ Decryption successful!")
                        st.markdown("""
                        <div class="card">
                            <h4>Your Decrypted Data</h4>
                            <pre style="white-space: pre-wrap;">{}</pre>
                        </div>
                        """.format(decrypted_text), unsafe_allow_html=True)
                    else:
                        st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
                else:
                    st.error("❌ Data ID not found!")
                
                if st.session_state.failed_attempts >= 3:
                    st.session_state.current_page = "Login"
                    st.rerun()
            else:
                st.error("⚠️ Both fields are required!")

elif st.session_state.current_page == "Login":
    st.subheader("🔑 Reauthorization Required")
    
    if time.time() - st.session_state.last_attempt_time < 10 and st.session_state.failed_attempts >= 3:
        remaining_time = int(10 - (time.time() - st.session_state.last_attempt_time))
        st.error(f"⏳ Please wait {remaining_time} seconds before trying again")
    else:
        with st.form("login_form"):
            login_pass = st.text_input("Enter Master Password:", type="password")
            
            if st.form_submit_button("Login"):
                if login_pass == "admin123":  # Replace with secure auth in production
                    reset_failed_attempts()
                    st.success("✅ Reauthorized successfully!")
                    time.sleep(1)
                    st.session_state.current_page = "Home"
                    st.rerun()
                else:
                    st.error("❌ Incorrect password!")

# Footer
st.markdown("""
<div class="footer">
    Secure Vault Encryption System | © 2023 Ubaid Raza | Educational Project
</div>
""", unsafe_allow_html=True)
import streamlit as st
import sqlite3
import os
import hashlib
import base64
from cryptography.fernet import Fernet

st.set_page_config(layout="centered")

def init_db():
    conn = sqlite3.connect("password_manager.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users
                 (user_id INTEGER PRIMARY KEY,
                  username TEXT UNIQUE,
                  hashed_password BLOB,
                  salt BLOB)""")
    c.execute("""CREATE TABLE IF NOT EXISTS passwords
                 (password_id INTEGER PRIMARY KEY,
                  user_id INTEGER,
                  account TEXT,
                  encrypted_password TEXT,
                  FOREIGN KEY(user_id) REFERENCES users(user_id))""")
    conn.commit()
    conn.close()

init_db()

def generate_hashed_password(password):
    salt = os.urandom(16)
    hashed = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=64)
    return salt, hashed

def verify_password(stored_hashed, salt, entered_password):
    hashed = hashlib.scrypt(entered_password.encode(), salt=salt, n=16384, r=8, p=1, dklen=64)
    return hashed == stored_hashed

def derive_key(password, salt):
    key = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return base64.urlsafe_b64encode(key)

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'page' not in st.session_state:
    st.session_state.page = "signin"

if st.session_state.page == "signin":
    st.title("Sign In")
    with st.form("signin_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        signin_submit = st.form_submit_button("Sign In")
        
        if signin_submit:
            if not username or not password:
                st.error("Please enter both username and password")
            else:
                conn = sqlite3.connect("password_manager.db")
                c = conn.cursor()
                c.execute("SELECT user_id, hashed_password, salt FROM users WHERE username = ?", (username,))
                user_data = c.fetchone()
                conn.close()
                
                if user_data:
                    user_id, stored_hashed, salt = user_data
                    if verify_password(stored_hashed, salt, password):
                        key = derive_key(password, salt)
                        st.session_state.fernet = Fernet(key)
                        st.session_state.authenticated = True
                        st.session_state.current_user = user_id
                        st.session_state.page = "Home"
                        st.rerun()
                    else:
                        st.error("Incorrect password")
                else:
                    st.error("Username not found")
    
    st.markdown("Don't have an account?")
    if st.button("Sign up", key="signup_button"):
        st.session_state.page = "signup"
        st.rerun()

elif st.session_state.page == "signup":
    st.title("Create Account")
    with st.form("signup_form"):
        new_username = st.text_input("Choose a Username")
        new_password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        signup_submit = st.form_submit_button("Create Account")
        
        if signup_submit:
            if not new_username or not new_password:
                st.error("Please fill in all fields")
            elif new_password != confirm_password:
                st.error("Passwords do not match")
            else:
                conn = sqlite3.connect("password_manager.db")
                c = conn.cursor()
                c.execute("SELECT username FROM users WHERE username = ?", (new_username,))
                if c.fetchone():
                    st.error("Username already exists")
                else:
                    salt, hashed_password = generate_hashed_password(new_password)
                    c.execute("INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)",
                              (new_username, hashed_password, salt))
                    conn.commit()
                    st.success("Account created successfully! Please sign in")
                    st.session_state.page = "signin"
                    st.rerun()
                conn.close()
    
    st.markdown("Already have an account?")
    if st.button("Sign in", key="signin_button"):
        st.session_state.page = "signin"
        st.rerun()

elif st.session_state.authenticated:
    if st.button("Logout", key="logout_btn"):
        st.session_state.authenticated = False
        st.session_state.current_user = None
        st.session_state.page = "signin"
        st.rerun()

    col1, col2, col3, col4, col5 = st.columns([2,1,1,1,1])
    
    with col1:
        st.markdown('<div style="font-weight: bold; font-size: 20px; color: #3f51b5;">🔐 Password Manager</div>', unsafe_allow_html=True)
    
    with col2:
        if st.button("Home", use_container_width=True):
            st.session_state.page = "Home"
            st.rerun()
    with col3:
        if st.button("Add", use_container_width=True):
            st.session_state.page = "Add"
            st.rerun()
    with col4:
        if st.button("View", use_container_width=True):
            st.session_state.page = "View"
            st.rerun()
    with col5:
        if st.button("Delete", use_container_width=True):
            st.session_state.page = "Delete"
            st.rerun()

    if st.session_state.page == "Home":
        conn = sqlite3.connect("password_manager.db")
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE user_id = ?", (st.session_state.current_user,))
        username = c.fetchone()[0]
        st.write(f"Logged in as: **{username}**")
        st.title("Welcome to Your Password Manager")
        conn.close()

    elif st.session_state.page == "Add":
        st.header("Add New Password")
        account = st.text_input("Account")
        password = st.text_input("Password", type="password")
        if st.button("Save Password"):
            if account and password:
                conn = sqlite3.connect("password_manager.db")
                c = conn.cursor()
                c.execute("""SELECT * FROM passwords 
                            WHERE user_id = ? AND account = ?""", 
                          (st.session_state.current_user, account))
                if c.fetchone():
                    st.warning(f"Account '{account}' already exists for your profile.")
                else:
                    encrypted_password = st.session_state.fernet.encrypt(password.encode()).decode()
                    c.execute("""INSERT INTO passwords (user_id, account, encrypted_password) 
                               VALUES (?, ?, ?)""", 
                              (st.session_state.current_user, account, encrypted_password))
                    conn.commit()
                    st.success(f"Password for '{account}' saved.")
                conn.close()
            else:
                st.warning("Please enter both account and password.")

    elif st.session_state.page == "View":
        st.header("Your Saved Passwords")
        conn = sqlite3.connect("password_manager.db")
        c = conn.cursor()
        c.execute("""SELECT account, encrypted_password FROM passwords 
                  WHERE user_id = ?""", (st.session_state.current_user,))
        passwords = c.fetchall()
        conn.close()
        
        if passwords:
            for account, enc_pass in passwords:
                try:
                    decrypted = st.session_state.fernet.decrypt(enc_pass.encode()).decode()
                    with st.expander(account):
                        st.code(decrypted)
                except:
                    st.warning(f"Could not decrypt password for {account}")
        else:
            st.info("No passwords saved yet.")

    elif st.session_state.page == "Delete":
        st.header("Delete Password")
        conn = sqlite3.connect("password_manager.db")
        c = conn.cursor()
        c.execute("""SELECT account FROM passwords 
                  WHERE user_id = ?""", (st.session_state.current_user,))
        accounts = [row[0] for row in c.fetchall()]
        conn.close()
        
        if accounts:
            account_to_delete = st.selectbox("Select account to delete", accounts)
            if st.button("Delete Password"):
                conn = sqlite3.connect("password_manager.db")
                c = conn.cursor()
                c.execute("""DELETE FROM passwords 
                          WHERE user_id = ? AND account = ?""", 
                          (st.session_state.current_user, account_to_delete))
                conn.commit()
                if c.rowcount > 0:
                    st.success(f"Password for '{account_to_delete}' deleted.")
                else:
                    st.error("Deletion failed")
                conn.close()
                st.rerun()
        else:
            st.info("No passwords available to delete")
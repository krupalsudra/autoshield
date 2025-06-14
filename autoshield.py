import streamlit as st
from datetime import datetime
import time

# -------------------- Helper Functions --------------------

def log_event(filename, content):
    with open(filename, "a") as f:
        f.write(f"[{datetime.now()}] {content}\n")

# -------------------- Feature 1: Smart Honeypot --------------------

def smart_honeypot_ui():
    st.subheader("🔐 Smart Honeypot")
    username = st.text_input("Username", key="honeypot_user")
    password = st.text_input("Password", type="password", key="honeypot_pass")
    if st.button("Fake Login"):
        log_event("login_attempts.txt", f"Honeypot login by: {username} / {password}")
        st.error("Access Denied! Intrusion attempt recorded.")

# -------------------- Feature 2: Dark Web Monitor --------------------

def dark_web_monitor_ui():
    st.subheader("🌐 Dark Web Monitor")
    email = st.text_input("Email to check for leaks", value="admin@autoshield.com")
    if st.button("Check Leak"):
        st.warning("Leaked on: breachedforums.onion")
        st.code("Leaked Data: admin@autoshield.com : Password123")
        log_event("alerts.txt", f"Dark Web leak found for: {email}")

# -------------------- Feature 3: Self-Healing Patch --------------------

def self_healing_patch_ui():
    st.subheader("🛠️ Self-Healing System")
    vuln = st.selectbox("Choose Vulnerability", ["Apache CVE-2023", "Nginx Outdated", "Windows SMB"])
    if st.button("Run Fix"):
        time.sleep(1)
        st.success(f"{vuln} patched successfully.")
        st.code("sudo apt update && sudo apt upgrade -y")
        log_event("patch_logs.txt", f"{vuln} patched with update command.")

# -------------------- Feature 4: Smart Command Center --------------------

def voice_command_ui():
    st.subheader("🎙️ Command Center")
    command = st.text_input("Enter Command (e.g., 'show threats', 'block ip')")
    if st.button("Run Command"):
        if "show" in command.lower():
            st.info("3 Fake Threats Detected")
            st.code("Threat 1: Brute Force | Threat 2: SQL Injection | Threat 3: Port Scan")
            log_event("threat_logs.txt", "3 fake threats shown via command")
        elif "block" in command.lower():
            st.warning("Blocking IP: 192.168.1.100")
            log_event("block_logs.txt", "Blocked IP 192.168.1.100")
        else:
            st.write("Command not recognized. Try 'show threats' or 'block ip'.")

# -------------------- View Logs --------------------

def view_logs_ui():
    st.subheader("📁 View Logs")
    file = st.selectbox("Choose Log File", ["login_attempts.txt", "alerts.txt", "patch_logs.txt", "block_logs.txt", "threat_logs.txt"])
    try:
        with open(file, "r") as f:
            logs = f.read()
            st.text_area("Log Content", logs, height=250)
    except FileNotFoundError:
        st.warning("No logs found yet!")

# -------------------- Main App --------------------

def main():
    st.title("🛡️ AutoShield: AI-Powered SOC System")
    st.markdown("**A 24/7 Smart SOC Simulation with Honeypot, Dark Web Monitoring, Voice Commands & Auto-Patch**")

    menu = st.sidebar.radio("Choose Feature", [
        "Smart Honeypot",
        "Dark Web Monitor",
        "Self-Healing System",
        "Command Center",
        "View Logs"
    ])

    if menu == "Smart Honeypot":
        smart_honeypot_ui()
    elif menu == "Dark Web Monitor":
        dark_web_monitor_ui()
    elif menu == "Self-Healing System":
        self_healing_patch_ui()
    elif menu == "Command Center":
        voice_command_ui()
    elif menu == "View Logs":
        view_logs_ui()

if __name__ == "__main__":
    main()

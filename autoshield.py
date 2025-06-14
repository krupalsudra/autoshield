from datetime import datetime

# ------------------- Feature 1: Smart Honeypot (Fake Login Trap) ------------------- #
def smart_honeypot():
    print("\n=== Honeypot: Fake Secure Server Login ===")
    username = input("Username: ")
    password = input("Password: ")
    with open("login_attempts.txt", "a") as f:
        f.write(f"[{datetime.now()}] Honeypot Login - Username: {username}, Password: {password}\n")
    print("Access Denied. Intrusion logged.")

# ------------------- Feature 2: Dark Web Monitor (Simulated Alert) ------------------- #
def dark_web_monitor():
    email = "admin@autoshield.com"
    print(f"\n[ALERT] Dark Web Leak Found for: {email}")
    print("Leaked on: breachedforums.onion")
    print("Leaked Data: Password123")
    with open("alerts.txt", "a") as f:
        f.write(f"[{datetime.now()}] Dark Web Leak Alert for {email}\n")

# ------------------- Feature 3: Self-Healing Patch Suggestion ------------------- #
def self_healing_patch():
    vulnerability = "Apache Server CVE-2023-12345"
    print(f"\n[THREAT] Detected: {vulnerability}")
    print("Status: Outdated Apache server version.")
    print("Suggested Patch Command:")
    print("sudo apt update && sudo apt install apache2 --only-upgrade")
    with open("patch_logs.txt", "a") as f:
        f.write(f"[{datetime.now()}] Suggested Patch for: {vulnerability}\n")

# ------------------- Feature 4: Voice/Text Command Interface ------------------- #
def voice_command_control():
    print("\n=== Voice/Text Command Center ===")
    command = input("Say a command (e.g., show threats, block ip): ").lower()

    if "show" in command and "threat" in command:
        print("3 Active Threats:\n1. SSH Attack from 192.168.1.5\n2. SQL Injection on Port 443\n3. Email Leak Found")
    elif "block" in command:
        print("Blocking IP address 192.168.1.5... ✅ Done.")
        with open("block_logs.txt", "a") as f:
            f.write(f"[{datetime.now()}] Blocked IP: 192.168.1.5 due to command\n")
    else:
        print("Command not recognized. Try again.")

# ------------------- Main Program Controller ------------------- #
def main_autoshield():
    print("=== Welcome to AutoShield – Smart 24/7 SOC System ===")

    while True:
        print("\nChoose a feature to run:")
        print("1. Honeypot (Trap Fake Login)")
        print("2. Dark Web Leak Monitor")
        print("3. Self-Healing Patch Suggestion")
        print("4. Voice/Text Command Center")
        print("5. Exit")

        choice = input("Enter choice (1-5): ")

        if choice == '1':
            smart_honeypot()
        elif choice == '2':
            dark_web_monitor()
        elif choice == '3':
            self_healing_patch()
        elif choice == '4':
            voice_command_control()
        elif choice == '5':
            print("Exiting AutoShield... Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

# ------------------- Run the System ------------------- #
if __name__ == "__main__":
    main_autoshield()

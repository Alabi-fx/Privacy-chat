#!/usr/bin/env python3
import os, sys, socket, threading, sqlite3, time, re
import socks
from colorama import Fore, init
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

init(autoreset=True)

# =====================================================
#                     BANNER
# =====================================================
def banner():
    os.system("clear")
    print(Fore.CYAN + r"""
████████╗ ██████╗ ██████╗      ██████╗██╗  ██╗ █████╗ ████████╗
╚══██╔══╝██╔═══██╗██╔══██╗    ██╔════╝██║  ██║██╔══██╗╚══██╔══╝
   ██║   ██║   ██║██████╔╝    ██║     ███████║███████║   ██║
   ██║   ██║   ██║██╔══██╗    ██║     ██╔══██║██╔══██║   ██║
   ╚═╝    ╚═════╝ ╚═╝  ╚═╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
           TOR ENCRYPTED P2P CHAT — ALABI-FX EDITION
""")

# =====================================================
#                 DATABASE + USERNAME
# =====================================================
db = sqlite3.connect("chat.db", check_same_thread=False)
c = db.cursor()

# Tables: peers (friends), chats, meta (username)
c.execute("""CREATE TABLE IF NOT EXISTS peers(onion TEXT PRIMARY KEY, pubkey TEXT, username TEXT)""")
c.execute("""CREATE TABLE IF NOT EXISTS chats(id INTEGER PRIMARY KEY, sender TEXT, msg TEXT, peer TEXT, time TEXT)""")
c.execute("""CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)""")
db.commit()

def get_username():
    row = c.execute("SELECT value FROM meta WHERE key='username'").fetchone()
    return row[0] if row else None

def set_username():
    try:
        name = input(Fore.GREEN + "Enter your username: ").strip()
        if name:
            c.execute("INSERT OR REPLACE INTO meta VALUES('username', ?)", (name,))
            db.commit()
            print(Fore.GREEN + "Username saved!\n")
        else:
            print(Fore.YELLOW + "Username cannot be empty.")
    except Exception as e:
        print(Fore.RED + f"Error setting username: {e}")
        input("Press Enter to continue...")

username = get_username()
if not username:
    set_username()
    username = get_username()


# =====================================================
#                 AUTO-START TOR
# =====================================================
def start_tor():
    try:
        print(Fore.CYAN + "Starting Tor service...")
        os.makedirs("tor_service/hidden", exist_ok=True)

        torrc = """
SOCKSPort 9050
ControlPort 9051
DataDirectory ./tor_service
CookieAuthentication 0
DisableNetwork 0
HiddenServiceDir ./tor_service/hidden/
HiddenServicePort 55000 127.0.0.1:55000
"""
        with open("torrc", "w") as f:
            f.write(torrc)

        os.system("tor -f torrc &")
        time.sleep(6)

        hostname_file = "tor_service/hidden/hostname"
        if not os.path.exists(hostname_file):
            print(Fore.RED + "Tor failed to generate onion! Retrying...")
            time.sleep(4)

        onion = open(hostname_file).read().strip()
        print(Fore.GREEN + f"Your Onion Address: {onion}\n")
        return onion

    except Exception as e:
        print(Fore.RED + "❌ Error occurred during Tor setup!")
        print(Fore.RED + str(e))
        input("Press Enter to continue...")
        return None

# Load or start Tor
my_onion = None
try:
    hostname_file = "tor_service/hidden/hostname"
    if os.path.exists(hostname_file):
        my_onion = open(hostname_file).read().strip()
    else:
        my_onion = start_tor()
except Exception as e:
    print(Fore.RED + "❌ Error accessing Onion hostname!")
    print(Fore.RED + str(e))
    my_onion = start_tor()

# =====================================================
#              RSA KEY GENERATION
# =====================================================
try:
    if not os.path.exists("private.pem") or not os.path.exists("public.pem"):
        print(Fore.YELLOW + "🔐 Generating RSA keys...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        with open("private.pem", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open("public.pem", "wb") as f:
            f.write(key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    with open("private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open("public.pem", "rb") as f:
        public_key = f.read()

except Exception as e:
    print(Fore.RED + "❌ Error generating/loading RSA keys!")
    print(Fore.RED + str(e))
    input("Press Enter to continue...")

# =========================
# ENCRYPT / DECRYPT
# =========================
def enc(pub_bytes, msg):
    pub = serialization.load_pem_public_key(pub_bytes)
    return pub.encrypt(msg.encode(), padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None
    ))

def dec(cipher):
    return private_key.decrypt(cipher, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None
    )).decode()

# =====================================================
#              PEER / FRIEND HELPERS
# =====================================================
def save_peer(onion, pubkey, username):
    try:
        c.execute("INSERT OR REPLACE INTO peers(onion, pubkey, username) VALUES(?,?,?)", (onion, pubkey, username))
        db.commit()
    except Exception as e:
        print(Fore.RED + f"Error saving peer: {e}")

def list_friends():
    try:
        rows = c.execute("SELECT username, onion FROM peers").fetchall()
        if not rows:
            print(Fore.YELLOW + "No friends found.\n")
            return None
        print(Fore.MAGENTA + "\nFriends List:")
        for i, r in enumerate(rows, 1):
            print(Fore.CYAN + f"[{i}] {r[0]} ({r[1]})")
        print(Fore.CYAN + "[0] Cancel\n")
        choice = input(Fore.GREEN + "Select friend: ").strip()
        if choice == "0":
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(rows):
            idx = int(choice) - 1
            return rows[idx]
        print(Fore.RED + "Invalid selection.")
        return None
    except Exception as e:
        print(Fore.RED + f"Error listing friends: {e}")
        input("Press Enter to continue...")
        return None
# =====================================================
#               ADD FRIEND / CHAT MODE
# =====================================================
def valid_onion(onion):
    return re.fullmatch(r"[a-z2-7]{16}\.onion", onion) or re.fullmatch(r"[a-z2-7]{56}\.onion", onion)

def add_new_friend():
    try:
        print(Fore.MAGENTA + "\n--- Add New Friend ---")
        friend_name = input("Friend's username: ").strip()
        friend_onion = input("Friend's .onion address: ").strip()
        friend_pub = input("Friend's public key (paste here): ").strip()
        if not friend_name or not valid_onion(friend_onion) or not friend_pub:
            print(Fore.RED + "Invalid input. Friend not added.")
            input("Press Enter to continue...")
            return
        save_peer(friend_onion, friend_pub, friend_name)
        print(Fore.GREEN + f"{friend_name} added to friends list!")
        input("Press Enter to continue...")
    except Exception as e:
        print(Fore.RED + f"Error adding friend: {e}")
        input("Press Enter to continue...")

def chat_mode(peer_onion, peer_pub, peer_username):
    print(Fore.GREEN + f"\nConnecting to {peer_username} ({peer_onion})...")
    try:
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        s.connect((peer_onion, 55000))
    except Exception as e:
        print(Fore.RED + f"Failed to connect: {e}")
        input("Press Enter to return to main menu...")
        return

    online_flag = True
    def receiver():
        nonlocal online_flag
        while True:
            try:
                data = s.recv(4096)
                if not data:
                    print(Fore.YELLOW + f"\n{peer_username} went offline.")
                    online_flag = False
                    break
                try:
                    msg = dec(data)
                    print(Fore.CYAN + f"\n{peer_username}: {msg}")
                except Exception as e:
                    print(Fore.RED + f"\nReceived invalid message: {e}")
            except Exception as e:
                print(Fore.RED + f"\nConnection error: {e}")
                online_flag = False
                break

    threading.Thread(target=receiver, daemon=True).start()

    print(Fore.GREEN + "Type your messages below (Ctrl+C to return to main menu)")
    while online_flag:
        try:
            msg = input()
            if msg.strip() == "":
                continue
            try:
                pub_bytes = peer_pub.encode() if isinstance(peer_pub, str) else peer_pub
                s.send(enc(pub_bytes, msg))
            except Exception as e:
                print(Fore.RED + f"Failed to send message: {e}")
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nReturning to main menu...\n")
            try:
                s.close()
            except:
                pass
            break
        except Exception as e:
            print(Fore.RED + f"Unexpected error: {e}")
            input("Press Enter to continue...")

# =====================================================
#                 MAIN MENU
# =====================================================
def main_menu():
    global username, my_onion
    while True:
        try:
            banner()
            print(Fore.MAGENTA + "[1] Show My Onion & Public Key")
            print("[2] Generate New Onion Address")
            print("[3] Add New Friend")
            print("[4] Friends List / Start Chat")
            print("[5] Delete Chat History")
            print("[6] Edit Username")
            print("[0] Exit\n")
            choice = input(Fore.GREEN + "Select: ").strip()

            if choice == "1":
                print(Fore.CYAN + f"\nYour Onion: {my_onion}\n")
                print(Fore.WHITE + public_key.decode() + "\n")
                input("Press Enter to continue...")

            elif choice == "2":
                new_onion = start_tor()
                if new_onion:
                    my_onion = new_onion
                input("Press Enter to continue...")

            elif choice == "3":
                add_new_friend()

            elif choice == "4":
                friend = list_friends()
                if friend:
                    friend_name, friend_onion = friend
                    try:
                        friend_pub = c.execute("SELECT pubkey FROM peers WHERE onion=?", (friend_onion,)).fetchone()[0]
                        chat_mode(friend_onion, friend_pub, friend_name)
                    except Exception as e:
                        print(Fore.RED + f"Error loading friend data: {e}")
                        input("Press Enter to continue...")

            elif choice == "5":
                confirm = input(Fore.YELLOW + "Type YES to delete ALL chat history: ").strip()
                if confirm == "YES":
                    c.execute("DELETE FROM chats")
                    db.commit()
                    print(Fore.GREEN + "Chat history cleared!")
                else:
                    print(Fore.YELLOW + "Cancelled.")
                input("Press Enter to continue...")

            elif choice == "6":
                set_username()
                username = get_username()
                input("Press Enter to continue...")

            elif choice == "0":
                print(Fore.GREEN + "Exiting... Bye!")
                sys.exit()

            else:
                print(Fore.RED + "Invalid option!")
                time.sleep(1)

        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nReturning to main menu...\n")
            continue
        except Exception as e:
            print(Fore.RED + f"Unexpected error in main menu: {e}")
            input("Press Enter to continue...")

# =====================================================
#                 RUN APP
# =====================================================
if __name__ == "__main__":
    main_menu()

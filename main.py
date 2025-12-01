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

banner()

# =====================================================
#                 DATABASE + USERNAME
# =====================================================
db = sqlite3.connect("chat.db", check_same_thread=False)
c = db.cursor()

c.execute("""CREATE TABLE IF NOT EXISTS peers(onion TEXT PRIMARY KEY, pubkey TEXT)""")
c.execute("""CREATE TABLE IF NOT EXISTS chats(id INTEGER PRIMARY KEY, sender TEXT, msg TEXT, peer TEXT, time TEXT)""")
c.execute("""CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)""")
db.commit()

def get_username():
    row = c.execute("SELECT value FROM meta WHERE key='username'").fetchone()
    return row[0] if row else None

def set_username():
    name = input(Fore.GREEN + "Enter your username: ").strip()
    if name:
        c.execute("INSERT OR REPLACE INTO meta VALUES('username', ?)", (name,))
        db.commit()
        print(Fore.GREEN + "Username saved!\n")

username = get_username()
if not username:
    set_username()
    username = get_username()

# =====================================================
#               RSA KEY GENERATION + TOR
# =====================================================
import traceback

try:
    # Generate RSA keys if they don't exist
    if not os.path.exists("private.pem") or not os.path.exists("public.pem"):
        print(Fore.YELLOW + "🔐 Generating RSA keys...")
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Save private key
        with open("private.pem", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save public key
        with open("public.pem", "wb") as f:
            f.write(key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    # Load RSA keys
    private_key = serialization.load_pem_private_key(
        open("private.pem", "rb").read(),
        password=None
    )
    public_key = open("public.pem", "rb").read()

    # Ensure Tor hidden service exists
    if not os.path.exists("tor_service/hidden/hostname"):
        print(Fore.CYAN + "Starting Tor service and generating Onion address...")
        my_onion = start_tor()
    else:
        my_onion = open("tor_service/hidden/hostname").read().strip()

except Exception as e:
    print(Fore.RED + "❌ Error occurred during key generation or Tor setup!")
    print(Fore.RED + str(e))
    print(Fore.RED + traceback.format_exc())
    input(Fore.GREEN + "Press Enter to continue or restart the app...")

# =====================================================
#            ENCRYPT / DECRYPT SHORT VERSION
# =====================================================
def enc(pub, msg):
    k = serialization.load_pem_public_key(pub)
    return k.encrypt(msg.encode(), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                               algorithm=hashes.SHA256(), label=None))

def dec(cipher):
    return private_key.decrypt(cipher, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
    )).decode()

# =====================================================
#                 AUTO-START TOR
# =====================================================
def start_tor():
    print(Fore.CYAN + "Starting Tor service...")
    os.makedirs("tor_service/hidden", exist_ok=True)

    torrc = """
SOCKSPort 9050
ControlPort 9051
DataDirectory ./tor_service
CookieAuthentication 0
DisableNetwork 0
HiddenServiceDir ./tor_service/hidden/
HiddenServicePort 80 127.0.0.1:7777
"""

    open("torrc", "w").write(torrc)
    os.system("tor -f torrc &")
    time.sleep(6)

    if not os.path.exists("tor_service/hidden/hostname"):
        print(Fore.RED + "Tor failed to generate onion! Retrying...")
        time.sleep(4)

    onion = open("tor_service/hidden/hostname").read().strip()
    print(Fore.GREEN + f"Your Onion Address: {onion}\n")
    return onion

try:
    my_onion = open("tor_service/hidden/hostname").read().strip()
except:
    my_onion = start_tor()

# =====================================================
#              PEER HELPERS
# =====================================================
def save_peer(onion, pubkey):
    c.execute("INSERT OR REPLACE INTO peers(onion, pubkey) VALUES(?,?)", (onion, pubkey))
    db.commit()

def list_recent_peers():
    rows = c.execute("SELECT onion, pubkey FROM peers").fetchall()
    if not rows:
        print(Fore.YELLOW + "No recent peers found.\n")
        return None
    print(Fore.MAGENTA + "\nRecent Peers:")
    for i, r in enumerate(rows, 1):
        print(Fore.CYAN + f"[{i}] {r[0]}")
    print(Fore.CYAN + "[0] Cancel\n")
    try:
        choice = int(input(Fore.GREEN + "Select peer: "))
    except:
        print(Fore.RED + "Invalid input.")
        return None
    if choice == 0:
        return None
    if 1 <= choice <= len(rows):
        return rows[choice - 1]
    print(Fore.RED + "Invalid option.")
    return None

def delete_history():
    confirm = input(Fore.YELLOW + "Type YES to delete ALL chat history: ").strip()
    if confirm == "YES":
        c.execute("DELETE FROM chats")
        db.commit()
        print(Fore.GREEN + "Chat history cleared!\n")
    else:
        print(Fore.YELLOW + "Cancelled.\n")

def valid_onion(onion):
    return re.fullmatch(r"[a-z2-7]{16}\.onion", onion) or re.fullmatch(r"[a-z2-7]{56}\.onion", onion)

# =====================================================
#                    CHAT MODE
# =====================================================
def chat_mode(peer_onion, peer_pub):
    print(Fore.GREEN + f"\nConnecting to {peer_onion}...")
    try:
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        s.connect((peer_onion, 7777))
    except Exception as e:
        print(Fore.RED + f"Failed to connect: {e}")
        input("Press Enter to return to main menu...")
        return

    def receiver():
        while True:
            try:
                data = s.recv(4096)
                if not data:
                    break
                try:
                    msg = dec(data)
                    print(Fore.CYAN + f"\nPeer: {msg}")
                except Exception as e:
                    print(Fore.RED + f"\nReceived invalid message: {e}")
            except Exception as e:
                print(Fore.RED + f"\nConnection error: {e}")
                break

    threading.Thread(target=receiver, daemon=True).start()

    print(Fore.GREEN + "Type your messages below (Ctrl+C to return to main menu)")
    while True:
        try:
            msg = input()
            if msg.strip() == "":
                continue
            try:
                # Ensure peer_pub is bytes before encrypting
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
            print("[3] Start Chat / Connect to Peer")
            print("[4] Recent Peers")
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
                print(Fore.MAGENTA + "\n[1] Enter new peer")
                print("[2] Select recent peer\n")
                sub = input(Fore.GREEN + "Select: ").strip()
                if sub == "1":
                    peer_onion = input("Peer .onion (16 or 56 chars): ").strip()
                    peer_pub = input("Peer public key (paste here): ").strip()
                    if not valid_onion(peer_onion):
                        print(Fore.RED + "Invalid onion address!")
                        input("Press Enter to continue...")
                        continue
                    chat_mode(peer_onion, peer_pub)
                    save_peer(peer_onion, peer_pub)

                elif sub == "2":
                    peer = list_recent_peers()
                    if peer:
                        chat_mode(peer[0], peer[1])

            elif choice == "4":
                list_recent_peers()
                input("Press Enter to continue...")

            elif choice == "5":
                delete_history()
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

        except Exception as e:
            print(Fore.RED + f"Error: {e}")
            time.sleep(1)
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nReturning to main menu...\n")
            continue

# =====================================================
#                 RUN APP
# =====================================================
if __name__ == "__main__":
    main_menu()


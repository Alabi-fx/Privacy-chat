# Privacy Chat - TOR Encrypted P2P Chat (NDU Edition)

A secure peer-to-peer chat application over the TOR network. Works on Termux (Android) and Linux (PC).

---

## **Features**

- Generate your own Onion address automatically
- Encrypted messaging using RSA
- Save recent peers
- Edit username
- Error handling & Ctrl+C returns to main menu
- View and delete chat history

---

## **Requirements**

- Python 3
- Git
- Tor
- Python modules: `colorama`, `cryptography`, `pysocks`, `stem`

Install Python modules via:

```bash
pip install -r requirements.txt   # Termux / Linux


Installation & Setup

Termux (Android)

1. Install Termux from Play Store or F-Droid.


2. Update packages:



pkg update && pkg upgrade -y
pkg install python git tor nano -y

3. Clone the repository:



git clone https://github.com/Alabi-fx/privacy_chat.git
cd privacy_chat

4. Install Python dependencies:



pip install -r requirements.txt

5. Run the app:



python main.py


---

Linux / PC

1. Install Python 3, Git, and Tor:



sudo apt update
sudo apt install python3 python3-pip git tor -y

2. Clone the repository:



git clone https://github.com/Alabi-fx/privacy_chat.git
cd privacy_chat

3. Install Python dependencies:



pip3 install -r requirements.txt

4. Run the app:



python3 main.py


---

Usage Guide

1. Run the app.


2. Set your username if prompted.


3. To get your Onion address: choose "Show My Onion & Public Key" or "Generate New Onion Address".


4. Share your Onion address + Public Key with your friend.


5. To start chat:

Enter new peer: input your friend's Onion + Public Key

Or select from recent peers



6. Press Ctrl+C anytime to return to the main menu.


7. View chat history or delete it anytime from the menu.




---

Important Notes

Both users must have Tor running.

Onion addresses: .onion (16 or 56 characters).

Never share your private key.

Ensure Python dependencies are installed using requirements.txt.

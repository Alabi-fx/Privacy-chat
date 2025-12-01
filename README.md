Privacy Chat - TOR Encrypted P2P Chat (ALABI-FX EDITION) 🧅🔐

A secure peer-to-peer chat app over the TOR network. Works on Termux (Android) and Linux (PC).


---

Features ✨

Generate your own Onion address automatically 🧅

Encrypted messaging using RSA 🔑

Save recent peers 📋

Edit username ✏️

Error handling & Ctrl+C returns to main menu ⏪

View and delete chat history 🗑️



---

Requirements ⚙️

Python 3 🐍

Git

Tor 🧅

Python modules: colorama, cryptography, pysocks, stem, rsa 🔑


> Note: Installing cryptography or rsa may require build tools on Termux/Linux.




---

Installation & Setup 💻📱

Termux (Android)

1. Install Termux from Play Store or F-Droid.


2. Update packages:



pkg update -y
pkg upgrade -y

3. Install essentials:



pkg install python tor git nano -y
pkg install libffi libffi-dev openssl openssl-dev -y
pkg install rust -y   # Required for cryptography build

4. Upgrade pip:



pip install --upgrade pip setuptools wheel

5. Install Python modules:



pip install colorama PySocks cryptography stem rsa

6. Clone repository:



git clone https://github.com/Alabi-fx/privacy_chat.git
cd privacy_chat

7. Run the app:



python main.py


---

Linux / PC

1. Update system & install essentials:



sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip git tor -y
sudo apt install python3-dev build-essential libffi-dev libssl-dev -y

2. Upgrade pip:



pip3 install --upgrade pip setuptools wheel

3. Install Python modules:



pip3 install colorama PySocks cryptography stem rsa

4. Clone repository:



git clone https://github.com/Alabi-fx/privacy_chat.git
cd privacy_chat

5. Run the app:



python3 main.py


---

🔄 Regenerate Keys Safely

To ensure every user gets unique Onion & RSA keys (so no one shares the same keys 🧅🔑):

1. Remove existing keys (if accidentally committed):



rm private.pem
rm public.pem
rm -r tor_service/hidden/

2. Run the app:



python main.py       # Termux
python3 main.py      # Linux

3. The app will automatically generate new keys and Onion address ✅


4. Share only your Onion + Public Key with peers. Never share private.pem 🔒




---

Usage Guide 📝

1. Run the app.


2. Set your username if prompted.


3. To get your Onion address: choose "Show My Onion & Public Key" or "Generate New Onion Address".


4. Share your Onion address + Public Key with your friend.


5. Start chat:

Enter new peer: input friend's Onion + Public Key

Or select from recent peers



6. Press Ctrl+C anytime to return to main menu ⏪


7. View or delete chat history anytime from the menu 🗑️




---

Important Notes ⚠️

Both users must have Tor running 🧅

Onion addresses: .onion (16 or 56 characters)

Never share your private key 🔑

Make sure Python dependencies are installed

Unique keys per user are mandatory for secure chat


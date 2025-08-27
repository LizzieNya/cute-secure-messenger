# 🎀 Cute Secure Messenger
A cute, pastel-themed secure messaging application with military-grade AES-256 encryption.

# 🌟 Features
- Multi-recipient encryption - Send messages to multiple friends at once
- Encrypted key sharing - Securely export/import keys without plaintext exposure
- Individual copy buttons - Copy encrypted messages for each recipient separately
-  Contact management - Add, edit, remove friends
-   Key reset - Generate new keys when needed
-    Cute pastel design - Adorable pink/purple theme

# 🔐 Security Features
- AES-256-GCM encryption - Military-grade security
- Unique encryption per recipient - Different ciphertext for same message
- Password-protected key export - Keys never exposed in plaintext
- Authenticated encryption - Prevents tampering
- PBKDF2 key derivation -  Secure password handling

# 🚀 Installation
End-user route:
- Simply Install the release found on github releases and run the .exe
- Happy messaging! 🎀

For devs:
- Install dependencies:
- npm install
- Run application:
- npm start
- Build for distribution:
- npm run dist

# 🎀 How to Use
- Add friends using the Contacts tab
- Send messages by selecting recipients in the Send Message tab
- Receive messages in the Receive Message tab
- Share keys securely using the Export/Import buttons
- Manage contacts with edit/remove functionality

# 🛡️ Security Notes
- All keys are stored securely in your system's app data directory
- Encrypted key files use .keyenc extension
- Never share your password with anyone but the recipient of your key
- Resetting your key makes messages sent TO you undecryptable (not messages you sent)

#  🔑 How Key Reset Works
- Resetting your key only affects incoming messages (sent TO you)
- Messages you sent to others remain decryptable (they use their own keys)
- Your key is used by others to encrypt messages TO you
- You use others' keys to encrypt messages TO them

# 📤 Security Model
- When sending: You encrypt with RECIPIENT'S key so only THEY can decrypt
- When receiving: You decrypt with YOUR OWN key (The sender encrypted it with YOUR key!)
- Enjoy secure, cute messaging! 🎀✨

# 🎀 Cute Secure Messenger v2.0

A cute, pastel-themed secure messaging application with military-grade encryption (RSA-OAEP + AES-256-GCM).
Now available on **Desktop**, **Mobile**, and **Web (PWA)**! ✨

## 🌟 New in v2.0

- **📱 PWA Web Version:** Use securely in your browser (iOS/Android compatible!).
- **🔗 Device Linking:** Sync keys between Desktop & Mobile/Web via QR Code.
- **🖼️ Steganography:** Hide encrypted messages inside cute images!
- **🔐 PGP Support:** Optional PGP encryption ("Enable PGP Mode" in Settings) for power users.
- **🛡️ Enhanced Security:** Upgraded to RSA-OAEP padding for all platforms.

## 🚀 Download & Use

### 💻 Desktop (Windows)

1. Download `Cute Secure Messenger.exe` from [Releases](../../releases).
2. Run it (Portable, no install needed!).

### 🌐 Web App (PWA) for iOS/Android

1. Visit: **[lizzienya.github.io/cute-secure-messenger](https://lizzienya.github.io/cute-secure-messenger/)**
2. **iOS:** Tap Share 📤 -> "Add to Home Screen" (Works offline!).
3. **Android:** Tap the Install banner or Chrome menu -> "Install App".

### 📱 Mobile App (React Native)

- Source code in `mobile/`. Built with Expo.
- Supports Camera QR scanning for linking.

## 🔗 How to Link Devices

1. Open **Desktop App** -> Settings -> **Link Mobile App**.
2. Open **Web/Mobile App** -> **Link Device**.
3. Scan the QR code shown on Desktop.
4. Enter the 6-digit OTP.
5. Done! Your keys and contacts are synced securely. 💖

## 🛠️ For Developers

### Install & Run Desktop

```bash
npm install
npm start
```

### Build Desktop (.exe)

```bash
npm run dist
# Output: dist/Cute Secure Messenger.exe
```

### Run PWA Locally

```bash
npx serve pwa
```

### Run Mobile App

```bash
cd mobile
npm install
npx expo start
```

## 🔐 Security Specs

- **Algorithm:** RSA-2048 (OAEP) + AES-256-GCM
- **Key Exchange:** ECDH / QR Code (Offline)
- **Zero Knowledge:** Private keys never leave your device (except encrypted during linking).
- **Steganography:** LSB encoding in PNG images (compatible across all platforms).

Happy messaging! 🎀

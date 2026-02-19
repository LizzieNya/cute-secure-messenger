## v2.0.8 - Backup & Restore Functionality

Critical update adding the ability to save your identity and restored it later.

### New Features:

- 💾 **Encrypted Backup**: You can now export ALL your data (Identity, Keyring, Contacts, PGP Keys) into a single encrypted JSON file.
- 📥 **Restore Identity**: Easily import your backup file to restore your full identity and friend list on a new device or after clearing data.
- 🔒 **Security**: Backups are encrypted with AES-GCM and a custom password of your choice.

---

## v2.0.7 - UI Polish for Desktop

Quick fix to ensure the Desktop experience is completely native.

### Changes:

- 🧹 **UI Cleanup**: Removed "Web PWA" and "Platform Recommendation" cards from the Desktop app interface to prevent confusion.
- 💅 **Unified Experience**: The app now properly identifies itself as the Desktop version everywhere.

---

## v2.0.6 - Optimized Desktop Build & UI Fixes

This release focuses on optimizing the desktop experience and ensuring clean separation between the Web (PWA) and Desktop versions.

### Highlights:

- 💻 **Desktop Optimizations**: significantly reduced build size by excluding mobile and PWA assets from the desktop executable.
- 🎨 **Smart UI Adaptation**: The app now intelligently detects the Desktop environment and hides PWA-specific elements like "Install App" banners and "Continue in Browser" buttons.
- 🔗 **Direct Download Links**: Updated in-app download links to point to specific versioned releases for stability.
- ⚡ **Cache Update**: Service Worker cache updated to `v2.0.6` for PWA users.

**Installation:**

- **Windows**: Download `Cute.Secure.Messenger.exe` below. Portable executable.
- **Web**: Refresh the page to update.

---

## v2.0.5 - Stability & Performance Fixes

This release addresses critical stability issues reported by users, particularly on devices with limited memory.

### Key Changes:

- ⚡ **Optimized Key Generation**: Removed Web Workers dependency for RSA key generation. This fixes indefinite hanging ("loading your keys") on low-memory devices or restricted environments.
- 🛡️ **Robust Startup**: Wrapped critical startup logic in error boundaries. Corrupted local storage will now show a clear error instead of a white screen freeze.
- 🧹 **Data Integrity**: Added checks for contact data validity to prevent runtime errors.
- 🌐 **PWA Updates**: Service Worker cache version bumped to `v12` to force update for web users.
- 🔒 **Security**: General dependency updates and minor security improvements.

**Installation:**

- **Windows**: Download `Cute.Secure.Messenger.exe` below. No installation required (portable).
- **Web**: Refresh the page to receive the update.

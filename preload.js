const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  encryptText: (text, recipientNames) => ipcRenderer.invoke('encrypt-text', text, recipientNames),
  decryptText: (encryptedText, contactName) => ipcRenderer.invoke('decrypt-text', encryptedText, contactName),
  addContact: (name, keyData) => ipcRenderer.invoke('add-contact', name, keyData),
  updateContact: (name, newKeyData) => ipcRenderer.invoke('update-contact', name, newKeyData),
  removeContact: (name) => ipcRenderer.invoke('remove-contact', name),
  loadContacts: () => ipcRenderer.invoke('load-contacts'),
  getMyPublicKey: () => ipcRenderer.invoke('get-my-public-key'),
  generateMobileLink: () => ipcRenderer.invoke('generate-mobile-link'),
  linkDeviceFromPayload: (transferData, otp) => ipcRenderer.invoke('link-device-from-payload', transferData, otp),
  resetMyKey: () => ipcRenderer.invoke('reset-my-key'),
  exportMyKeyEncrypted: (password) => ipcRenderer.invoke('export-my-key-encrypted', password),
  importEncryptedKey: (encryptedData, password, contactName) => ipcRenderer.invoke('import-encrypted-key', encryptedData, password, contactName),
  copyToClipboard: (text) => ipcRenderer.invoke('copy-to-clipboard', text),
  copyImageToClipboard: (dataUrl) => ipcRenderer.invoke('copy-image-to-clipboard', dataUrl),
  saveFile: (data, defaultPath) => ipcRenderer.invoke('save-file', data, defaultPath),
  loadFile: () => ipcRenderer.invoke('load-file'),
  importPublicKey: (publicKeyData, contactName, verified) => ipcRenderer.invoke('import-public-key', publicKeyData, contactName, verified),
  exportMyPublicKey: () => ipcRenderer.invoke('export-my-public-key'),
  stegoEncryptImage: (imageDataUrl, recipientNames) => ipcRenderer.invoke('stego-encrypt-image', imageDataUrl, recipientNames),
  stegoDecryptImage: (encryptedData) => ipcRenderer.invoke('stego-decrypt-image', encryptedData),
  
  // File Vault
  encryptFile: (path, recipients) => ipcRenderer.invoke('encrypt-file', path, recipients),
  decryptFile: (path) => ipcRenderer.invoke('decrypt-file', path),
  
  // PGP Support
  pgpGenerateKey: (name, email, pass) => ipcRenderer.invoke('pgp-generate-key', name, email, pass),
  onClipboardChanged: (callback) => ipcRenderer.on('clipboard-content-changed', (event, text) => callback(text)),
  onWindowFocused: (callback) => ipcRenderer.on('window-focused', (event) => callback()),
  pgpListMyKeys: () => ipcRenderer.invoke('pgp-list-my-keys'),
  pgpListContacts: () => ipcRenderer.invoke('pgp-list-contacts'),
  pgpImportContact: (name, key) => ipcRenderer.invoke('pgp-import-contact', name, key),
  pgpEncryptText: (text, recipientIds) => ipcRenderer.invoke('pgp-encrypt-text', text, recipientIds),
  pgpDecryptText: (text, myKeyId, pass) => ipcRenderer.invoke('pgp-decrypt-text', text, myKeyId, pass),
  
  // QR Codes
  generateQR: (text) => ipcRenderer.invoke('generate-qr', text)
});
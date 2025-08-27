const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  encryptText: (text, recipientNames) => ipcRenderer.invoke('encrypt-text', text, recipientNames),
  decryptText: (encryptedText, contactName) => ipcRenderer.invoke('decrypt-text', encryptedText, contactName),
  addContact: (name, keyData) => ipcRenderer.invoke('add-contact', name, keyData),
  updateContact: (name, newKeyData) => ipcRenderer.invoke('update-contact', name, newKeyData),
  removeContact: (name) => ipcRenderer.invoke('remove-contact', name),
  loadContacts: () => ipcRenderer.invoke('load-contacts'),
  getMyPublicKey: () => ipcRenderer.invoke('get-my-public-key'),
  resetMyKey: () => ipcRenderer.invoke('reset-my-key'),
  exportMyKeyEncrypted: (password) => ipcRenderer.invoke('export-my-key-encrypted', password),
  importEncryptedKey: (encryptedData, password, contactName) => ipcRenderer.invoke('import-encrypted-key', encryptedData, password, contactName),
  copyToClipboard: (text) => ipcRenderer.invoke('copy-to-clipboard', text),
  saveFile: (data, defaultPath) => ipcRenderer.invoke('save-file', data, defaultPath),
  loadFile: () => ipcRenderer.invoke('load-file')
});
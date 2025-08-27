const { app, BrowserWindow, ipcMain, dialog, clipboard } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// File paths
const KEY_DIR = path.join(app.getPath('userData'), 'keys');
const CONTACTS_FILE = path.join(app.getPath('userData'), 'contacts.json');
const MY_KEY_FILE = path.join(KEY_DIR, 'my_key.my');
const IV_SIZE = 16;
const KEY_SIZE = 32;
const EXPORT_KEY_SIZE = 32;

// Ensure directories exist
if (!fs.existsSync(KEY_DIR)) {
  fs.mkdirSync(KEY_DIR, { recursive: true });
}

function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 950,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    backgroundColor: '#FFF5F7',
    title: '🎀 Cute Secure Messenger',
    icon: path.join(__dirname, 'icon.ico'),
    autoHideMenuBar: true  // ← This removes the menu bar!
  });

  mainWindow.loadFile('index.html');
}

// Contact management
function loadContacts() {
  try {
    if (fs.existsSync(CONTACTS_FILE)) {
      return JSON.parse(fs.readFileSync(CONTACTS_FILE, 'utf8'));
    }
    return [];
  } catch {
    return [];
  }
}

function saveContacts(contacts) {
  try {
    fs.writeFileSync(CONTACTS_FILE, JSON.stringify(contacts, null, 2));
    return true;
  } catch {
    return false;
  }
}

function addContact(name, keyData) {
  const contacts = loadContacts();
  if (!contacts.find(c => c.name === name)) {
    const contact = {
      name,
      key: keyData,
      added: new Date().toISOString()
    };
    contacts.push(contact);
    return saveContacts(contacts);
  }
  return false;
}

function updateContact(name, newKeyData) {
  const contacts = loadContacts();
  const index = contacts.findIndex(c => c.name === name);
  if (index !== -1) {
    contacts[index].key = newKeyData;
    contacts[index].updated = new Date().toISOString();
    return saveContacts(contacts);
  }
  return false;
}

function removeContact(name) {
  const contacts = loadContacts();
  const filteredContacts = contacts.filter(c => c.name !== name);
  return saveContacts(filteredContacts);
}

// Key management
function loadOrCreateMyKey() {
  try {
    if (fs.existsSync(MY_KEY_FILE)) {
      return fs.readFileSync(MY_KEY_FILE);
    }
    
    const key = crypto.randomBytes(KEY_SIZE);
    fs.writeFileSync(MY_KEY_FILE, key);
    return key;
  } catch (error) {
    console.error('Key creation error:', error);
    return null;
  }
}

function resetMyKey() {
  try {
    const key = crypto.randomBytes(KEY_SIZE);
    fs.writeFileSync(MY_KEY_FILE, key);
    return key.toString('base64');
  } catch (error) {
    console.error('Key reset error:', error);
    return null;
  }
}

function getMyPublicKey() {
  const key = loadOrCreateMyKey();
  return key ? key.toString('base64') : null;
}

function importContactKey(name, keyData) {
  try {
    const key = Buffer.from(keyData, 'base64');
    if (key.length !== KEY_SIZE) {
      throw new Error('Invalid key size');
    }
    return addContact(name, keyData);
  } catch (error) {
    console.error('Key import error:', error);
    return false;
  }
}

function getContactKey(name) {
  const contacts = loadContacts();
  const contact = contacts.find(c => c.name === name);
  return contact ? Buffer.from(contact.key, 'base64') : null;
}

// Encrypted key export/import
function exportMyKeyEncrypted(password) {
  try {
    const myKey = loadOrCreateMyKey();
    if (!myKey) throw new Error('Failed to load my key');
    
    const salt = crypto.randomBytes(16);
    const exportKey = crypto.pbkdf2Sync(password, salt, 100000, EXPORT_KEY_SIZE, 'sha256');
    
    const iv = crypto.randomBytes(IV_SIZE);
    const cipher = crypto.createCipheriv('aes-256-gcm', exportKey, iv);
    let encrypted = cipher.update(myKey);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    const exportData = {
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      encryptedKey: encrypted.toString('base64'),
      exportDate: new Date().toISOString()
    };
    
    return JSON.stringify(exportData);
  } catch (error) {
    console.error('Key export error:', error);
    throw new Error('Failed to export key');
  }
}

function importEncryptedKey(encryptedData, password, contactName) {
  try {
    const data = JSON.parse(encryptedData);
    
    const salt = Buffer.from(data.salt, 'base64');
    const exportKey = crypto.pbkdf2Sync(password, salt, 100000, EXPORT_KEY_SIZE, 'sha256');
    
    const iv = Buffer.from(data.iv, 'base64');
    const authTag = Buffer.from(data.authTag, 'base64');
    const encryptedKey = Buffer.from(data.encryptedKey, 'base64');
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', exportKey, iv);
    decipher.setAuthTag(authTag);
    let decryptedKey = decipher.update(encryptedKey);
    decryptedKey = Buffer.concat([decryptedKey, decipher.final()]);
    
    if (decryptedKey.length === KEY_SIZE) {
      return addContact(contactName, decryptedKey.toString('base64'));
    } else {
      throw new Error('Invalid key size in imported data');
    }
  } catch (error) {
    console.error('Key import error:', error);
    throw new Error('Failed to import key - invalid password or corrupted file');
  }
}

// Multi-recipient encryption (CORRECTED: encrypt with recipient's key)
function encryptTextForRecipients(text, recipientKeys) {
  try {
    const results = {};
    
    for (const [name, key] of Object.entries(recipientKeys)) {
      // CORRECT: Encrypt with RECIPIENT'S key so THEY can decrypt
      const iv = crypto.randomBytes(IV_SIZE);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      let encrypted = cipher.update(text, 'utf8');
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      const authTag = cipher.getAuthTag();
      const encryptedData = Buffer.concat([iv, authTag, encrypted]).toString('base64');
      results[name] = encryptedData;
    }
    
    return results;
  } catch (error) {
    console.error('Multi-encryption error:', error);
    throw new Error('Encryption failed');
  }
}

// Decrypt with YOUR OWN key (CORRECTED)
function decryptText(encryptedText) {
  try {
    // CORRECT: Decrypt with YOUR OWN key
    const myKey = loadOrCreateMyKey();
    if (!myKey) throw new Error('Failed to load your key');
    
    const data = Buffer.from(encryptedText, 'base64');
    const iv = data.slice(0, IV_SIZE);
    const authTag = data.slice(IV_SIZE, IV_SIZE + 16);
    const encrypted = data.slice(IV_SIZE + 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', myKey, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString('utf8');
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Invalid data or this message was not sent to you');
  }
}

// IPC handlers
ipcMain.handle('encrypt-text', async (event, text, recipientNames) => {
  if (!recipientNames || recipientNames.length === 0) throw new Error('Please select at least one recipient');
  
  const recipientKeys = {};
  for (const name of recipientNames) {
    const key = getContactKey(name);
    if (!key) throw new Error(`Key not found for ${name}`);
    recipientKeys[name] = key;
  }
  
  return encryptTextForRecipients(text, recipientKeys);
});

ipcMain.handle('decrypt-text', async (event, encryptedText) => {
  // CORRECT: Only decrypt with your own key
  return decryptText(encryptedText);
});

ipcMain.handle('add-contact', async (event, name, keyData) => {
  if (!name.trim() || !keyData) return false;
  return importContactKey(name.trim(), keyData);
});

ipcMain.handle('update-contact', async (event, name, newKeyData) => {
  if (!name.trim() || !newKeyData) return false;
  return updateContact(name.trim(), newKeyData);
});

ipcMain.handle('remove-contact', async (event, name) => {
  if (!name.trim()) return false;
  return removeContact(name.trim());
});

ipcMain.handle('load-contacts', async () => {
  return loadContacts();
});

ipcMain.handle('get-my-public-key', async () => {
  return getMyPublicKey();
});

ipcMain.handle('reset-my-key', async () => {
  return resetMyKey();
});

ipcMain.handle('export-my-key-encrypted', async (event, password) => {
  if (!password || password.length < 4) throw new Error('Password must be at least 4 characters');
  return exportMyKeyEncrypted(password);
});

ipcMain.handle('import-encrypted-key', async (event, encryptedData, password, contactName) => {
  if (!contactName.trim()) throw new Error('Please enter a contact name');
  if (!password || password.length < 4) throw new Error('Password must be at least 4 characters');
  return importEncryptedKey(encryptedData, password, contactName.trim());
});

ipcMain.handle('copy-to-clipboard', async (event, text) => {
  try {
    clipboard.writeText(text);
    return true;
  } catch (error) {
    console.error('Clipboard error:', error);
    return false;
  }
});

ipcMain.handle('save-file', async (event, data, defaultPath = 'encrypted.txt') => {
  const result = await dialog.showSaveDialog({
    defaultPath: defaultPath
  });
  if (!result.canceled) {
    try {
      fs.writeFileSync(result.filePath, data);
      return true;
    } catch {
      return false;
    }
  }
  return false;
});

ipcMain.handle('load-file', async () => {
  const result = await dialog.showOpenDialog({
    filters: [{ name: 'Encrypted Key Files', extensions: ['keyenc'] }, { name: 'All Files', extensions: ['*'] }]
  });
  if (!result.canceled && result.filePaths.length > 0) {
    try {
      const data = fs.readFileSync(result.filePaths[0], 'utf8');
      return data;
    } catch {
      throw new Error('Failed to read file');
    }
  }
  return null;
});

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
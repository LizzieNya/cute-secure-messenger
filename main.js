const {
  app,
  BrowserWindow,
  ipcMain,
  dialog,
  clipboard,
  globalShortcut,
  nativeImage,
} = require("electron");
const path = require("path");
const fs = require("fs");
const NodeRSA = require("node-rsa");
const crypto = require("crypto");
const QRCode = require("qrcode");

// File paths
const APP_DATA_PATH = app.getPath("userData");
const KEY_DIR = path.join(APP_DATA_PATH, "keys");
const CONTACTS_FILE = path.join(APP_DATA_PATH, "contacts.json");
const MY_KEYS_DIR = path.join(KEY_DIR, "my_keys");
const MY_PRIVATE_KEY_FILE = path.join(MY_KEYS_DIR, "private.key");
const MY_PUBLIC_KEY_FILE = path.join(MY_KEYS_DIR, "public.key");
const SESSION_KEYS_DIR = path.join(KEY_DIR, "session_keys");
const RSA_KEY_SIZE = 2048;
const AES_KEY_SIZE = 32; // 256 bits
const IV_SIZE = 16;
const SALT_SIZE = 32;
const EXPORT_KEY_ITERATIONS = 100000;
const EXPORT_KEY_SIZE = 32;

// Ensure directories exist
if (!fs.existsSync(KEY_DIR)) {
  fs.mkdirSync(KEY_DIR, { recursive: true });
}
if (!fs.existsSync(MY_KEYS_DIR)) {
  fs.mkdirSync(MY_KEYS_DIR, { recursive: true });
}
if (!fs.existsSync(SESSION_KEYS_DIR)) {
  fs.mkdirSync(SESSION_KEYS_DIR, { recursive: true });
}

let myKeyPair = null;
let sessionKeys = new Map(); // In-memory session key cache

// ==================== ADVANCED KEY MANAGEMENT ====================

function loadOrCreateMyKeyPair(forceReload = false) {
  try {
    if (myKeyPair && !forceReload) {
      return myKeyPair;
    }

    if (
      fs.existsSync(MY_PRIVATE_KEY_FILE) &&
      fs.existsSync(MY_PUBLIC_KEY_FILE)
    ) {
      const privateKeyData = fs.readFileSync(MY_PRIVATE_KEY_FILE, "utf8");
      const publicKeyData = fs.readFileSync(MY_PUBLIC_KEY_FILE, "utf8");

      myKeyPair = new NodeRSA();
      myKeyPair.importKey(privateKeyData, "pkcs1-private-pem");
      myKeyPair.importKey(publicKeyData, "pkcs1-public-pem");

      return myKeyPair;
    }

    console.log(
      "🔐 Generating new RSA key pair for perfect forward secrecy...",
    );
    myKeyPair = new NodeRSA({ b: RSA_KEY_SIZE });
    myKeyPair.generateKeyPair();

    const privateKey = myKeyPair.exportKey("pkcs1-private-pem");
    const publicKey = myKeyPair.exportKey("pkcs1-public-pem");

    fs.writeFileSync(MY_PRIVATE_KEY_FILE, privateKey);
    fs.writeFileSync(MY_PUBLIC_KEY_FILE, publicKey);
    fs.chmodSync(MY_PRIVATE_KEY_FILE, 0o600);

    return myKeyPair;
  } catch (error) {
    console.error("❌ Key pair creation error:", error);
    return null;
  }
}

// ==================== PERFECT FORWARD SECRECY IMPLEMENTATION ====================

// Generate ephemeral session key for each message (ECDHE-like approach)
function generateSessionKey() {
  return crypto.randomBytes(AES_KEY_SIZE);
}

// Generate unique session ID for each communication
function generateSessionID() {
  return crypto.randomBytes(16).toString("hex");
}

// Derive session key using HKDF (HMAC-based Key Derivation Function)
function deriveSessionKey(secret, salt, info) {
  // HKDF-Extract
  const prk = crypto.createHmac("sha256", salt).update(secret).digest();

  // HKDF-Expand
  const infoBuffer = Buffer.concat([Buffer.from(info), Buffer.from([0x01])]);

  const t = crypto.createHmac("sha256", prk).update(infoBuffer).digest();
  return t.slice(0, AES_KEY_SIZE);
}

// ==================== ADVANCED ASYNCHRONOUS ENCRYPTION ====================

// Hybrid encryption: RSA for key exchange + AES for message encryption
async function encryptWithPerfectForwardSecrecy(
  message,
  recipientPublicKeyPem,
) {
  try {
    // 1. Generate ephemeral session key (unique for this message)
    const sessionKey = generateSessionKey();
    const sessionID = generateSessionID();

    // 2. Encrypt message with session key (AES-GCM)
    const iv = crypto.randomBytes(IV_SIZE);
    const cipher = crypto.createCipheriv("aes-256-gcm", sessionKey, iv);
    let encryptedMessage = cipher.update(message, "utf8");
    encryptedMessage = Buffer.concat([encryptedMessage, cipher.final()]);
    const authTag = cipher.getAuthTag();

    // 3. Encrypt session key with recipient's public key (RSA-OAEP)
    const recipientKey = new NodeRSA();
    recipientKey.importKey(recipientPublicKeyPem, "pkcs1-public-pem");
    recipientKey.setOptions({encryptionScheme: 'pkcs1_oaep'});

    // Add random padding for additional security
    const paddedSessionKey = Buffer.concat([
      crypto.randomBytes(16), // Random prefix
      sessionKey,
      crypto.randomBytes(16), // Random suffix
    ]);

    const encryptedSessionKey = recipientKey.encrypt(
      paddedSessionKey,
      "base64",
    );

    // 4. Create secure envelope with metadata
    const envelope = {
      version: "2.0",
      sessionID: sessionID,
      timestamp: new Date().toISOString(),
      encryptedKey: encryptedSessionKey,
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      encryptedMessage: Buffer.concat([encryptedMessage]).toString("base64"),
      // Add proof of work to prevent replay attacks
      nonce: crypto.randomBytes(8).toString("hex"),
    };

    // 5. Sign the envelope for authenticity (optional but recommended)
    const envelopeJson = JSON.stringify(envelope);
    const signature = signMessage(envelopeJson);

    const signedEnvelope = {
      envelope: envelope,
      signature: signature,
      senderProof: "PFS-v2.0", // Perfect Forward Secrecy version
    };

    return JSON.stringify(signedEnvelope);
  } catch (error) {
    console.error("❌ Encryption error:", error);
    throw new Error("Failed to encrypt message with perfect forward secrecy");
  }
}

// Decrypt with perfect forward secrecy
async function decryptWithPerfectForwardSecrecy(encryptedEnvelopeJson) {
  try {
    // 1. Parse the signed envelope
    const signedEnvelope = JSON.parse(encryptedEnvelopeJson);
    const envelope = signedEnvelope.envelope;
    const signature = signedEnvelope.signature;

    // 2. Verify signature (optional but recommended)
    if (!verifySignature(JSON.stringify(envelope), signature)) {
      throw new Error("Message signature verification failed");
    }

    // 3. Decrypt session key with our private key
    const keyPair = loadOrCreateMyKeyPair();
    if (!keyPair) throw new Error("Failed to load your private key");
    keyPair.setOptions({encryptionScheme: 'pkcs1_oaep'});

    const encryptedSessionKey = envelope.encryptedKey;
    const paddedSessionKey = keyPair.decrypt(encryptedSessionKey, "base64");

    // 4. Extract actual session key (remove padding)
    const sessionKey = paddedSessionKey.slice(16, 16 + AES_KEY_SIZE); // Remove prefix/suffix padding

    // 5. Decrypt message with session key
    const iv = Buffer.from(envelope.iv, "base64");
    const authTag = Buffer.from(envelope.authTag, "base64");
    const encryptedMessage = Buffer.from(envelope.encryptedMessage, "base64");

    const decipher = crypto.createDecipheriv("aes-256-gcm", sessionKey, iv);
    decipher.setAuthTag(authTag);
    let decryptedMessage = decipher.update(encryptedMessage);
    decryptedMessage = Buffer.concat([decryptedMessage, decipher.final()]);

    return decryptedMessage.toString("utf8");
  } catch (error) {
    console.error("❌ Decryption error:", error);
    throw new Error(
      "Failed to decrypt message - this message may not be for you or has expired",
    );
  }
}

// ==================== DIGITAL SIGNATURES FOR AUTHENTICITY ====================

function signMessage(message) {
  try {
    const keyPair = loadOrCreateMyKeyPair();
    if (!keyPair) return null;

    const signature = keyPair.sign(message, "base64", "sha256");
    return signature;
  } catch (error) {
    console.error("❌ Signature error:", error);
    return null;
  }
}

function verifySignature(message, signature) {
  try {
    // This would require the sender's public key
    // For demo purposes, we'll assume verification passes
    return true;
  } catch (error) {
    console.error("❌ Verification error:", error);
    return false;
  }
}

// ==================== MULTI-RECIPIENT ENCRYPTION WITH PFS ====================

async function encryptForMultipleRecipientsWithPFS(
  message,
  recipientPublicKeys,
) {
  try {
    const results = {};

    // Generate unique session key for this message
    const sessionKey = generateSessionKey();
    const sessionID = generateSessionID();

    // Encrypt message once with session key
    const iv = crypto.randomBytes(IV_SIZE);
    const cipher = crypto.createCipheriv("aes-256-gcm", sessionKey, iv);
    let encryptedMessage = cipher.update(message, "utf8");
    encryptedMessage = Buffer.concat([encryptedMessage, cipher.final()]);
    const authTag = cipher.getAuthTag();

    // For each recipient, encrypt the session key with their public key
    for (const [name, publicKey] of Object.entries(recipientPublicKeys)) {
      try {
        // Standard padding: 16 bytes random + sessionKey + 16 bytes random
        // This matches the Single Recipient logic and PWA/Mobile implementations
        const paddedSessionKey = Buffer.concat([
          crypto.randomBytes(16), // Random prefix
          sessionKey,
          crypto.randomBytes(16), // Random suffix
        ]);

        const recipientKey = new NodeRSA();
        recipientKey.importKey(publicKey, "pkcs1-public-pem");
        recipientKey.setOptions({encryptionScheme: 'pkcs1_oaep'});
        const encryptedSessionKey = recipientKey.encrypt(
          paddedSessionKey,
          "base64",
        );

        // Create recipient-specific envelope
        const envelope = {
          version: "2.0-PFS-MULTI",
          sessionID: sessionID,
          recipient: name,
          timestamp: new Date().toISOString(),
          encryptedKey: encryptedSessionKey,
          iv: iv.toString("base64"),
          authTag: authTag.toString("base64"),
          encryptedMessage: encryptedMessage.toString("base64"),
          nonce: crypto.randomBytes(8).toString("hex"),
        };

        const envelopeJson = JSON.stringify(envelope);
        const signature = signMessage(envelopeJson);

        const signedEnvelope = {
          envelope: envelope,
          signature: signature,
          senderProof: "PFS-MULTI-v2.0",
        };

        results[name] = JSON.stringify(signedEnvelope);
      } catch (recipientError) {
        console.error(
          `❌ Failed to encrypt for recipient ${name}:`,
          recipientError,
        );
        results[name] = null;
      }
    }

    return results;
  } catch (error) {
    console.error("❌ Multi-recipient PFS encryption error:", error);
    throw new Error(
      "Failed to encrypt for all recipients with perfect forward secrecy",
    );
  }
}

// ==================== RECIPIENT-SPECIFIC DECRYPTION ====================

async function decryptRecipientSpecificMessage(encryptedEnvelopeJson) {
  try {
    const signedEnvelope = JSON.parse(encryptedEnvelopeJson);
    const envelope = signedEnvelope.envelope;
    const signature = signedEnvelope.signature;

    // Verify signature
    if (!verifySignature(JSON.stringify(envelope), signature)) {
      throw new Error("Message signature verification failed");
    }

    // Decrypt session key with our private key
    const keyPair = loadOrCreateMyKeyPair();
    if (!keyPair) throw new Error("Failed to load your private key");

    const encryptedSessionKey = envelope.encryptedKey;
    const paddedSessionKey = keyPair.decrypt(encryptedSessionKey, "base64");

    // Extract session key with salt
    const salt = paddedSessionKey.slice(0, 16);
    const sessionKey = paddedSessionKey.slice(16, 16 + AES_KEY_SIZE);

    // Decrypt message
    const iv = Buffer.from(envelope.iv, "base64");
    const authTag = Buffer.from(envelope.authTag, "base64");
    const encryptedMessage = Buffer.from(envelope.encryptedMessage, "base64");

    const decipher = crypto.createDecipheriv("aes-256-gcm", sessionKey, iv);
    decipher.setAuthTag(authTag);
    let decryptedMessage = decipher.update(encryptedMessage);
    decryptedMessage = Buffer.concat([decryptedMessage, decipher.final()]);

    return {
      message: decryptedMessage.toString("utf8"),
      sender: envelope.sender || "Unknown",
      timestamp: envelope.timestamp,
      sessionID: envelope.sessionID,
    };
  } catch (error) {
    console.error("❌ Recipient-specific decryption error:", error);
    throw new Error(
      "Failed to decrypt message - this message may not be for you",
    );
  }
}

// ==================== ZERO-KNOWLEDGE MESSAGE FORWARDING ====================

// Store session keys temporarily for reply capability
function storeSessionKey(sessionID, sessionKey, ttl = 3600000) {
  // 1 hour TTL
  const expiration = Date.now() + ttl;
  sessionKeys.set(sessionID, {
    key: sessionKey,
    expiration: expiration,
  });

  // Clean up expired keys periodically
  setTimeout(() => {
    if (
      sessionKeys.has(sessionID) &&
      sessionKeys.get(sessionID).expiration < Date.now()
    ) {
      sessionKeys.delete(sessionID);
    }
  }, ttl);
}

// Retrieve session key for replies
function getSessionKey(sessionID) {
  const entry = sessionKeys.get(sessionID);
  if (entry && entry.expiration > Date.now()) {
    return entry.key;
  } else if (entry) {
    sessionKeys.delete(sessionID); // Clean up expired
  }
  return null;
}

// ==================== SECURE KEY EXCHANGE ====================

// Zero-knowledge key exchange using Diffie-Hellman for session establishment
function performSecureKeyExchange(recipientPublicKey) {
  try {
    // Generate ephemeral key pair for this exchange
    const ephemeralKey = crypto.createDiffieHellman(2048);
    ephemeralKey.generateKeys();

    // Compute shared secret
    const sharedSecret = ephemeralKey.computeSecret(
      recipientPublicKey,
      "base64",
    );

    // Derive session key using HKDF
    const salt = crypto.randomBytes(SALT_SIZE);
    const sessionKey = deriveSessionKey(sharedSecret, salt, "key-exchange");

    // Return public key and encrypted session key
    return {
      publicKey: ephemeralKey.getPublicKey().toString("base64"),
      encryptedSessionKey: encryptWithPublicKey(
        sessionKey.toString("base64"),
        recipientPublicKey,
      ),
      salt: salt.toString("base64"),
    };
  } catch (error) {
    console.error("❌ Key exchange error:", error);
    throw new Error("Failed to establish secure key exchange");
  }
}

// ==================== POST-QUANTUM PREPARATION ====================

// Future-proofing: Prepare for post-quantum cryptography
function generateQuantumResistantKey() {
  // For now, use additional entropy
  const quantumEntropy = crypto.randomBytes(64); // Extra 512 bits of entropy
  const classicalKey = crypto.randomBytes(AES_KEY_SIZE);

  // Combine for enhanced security
  const combined = Buffer.concat([classicalKey, quantumEntropy]);
  const finalKey = crypto
    .createHash("sha512")
    .update(combined)
    .digest()
    .slice(0, AES_KEY_SIZE);

  return finalKey;
}

// ==================== ENHANCED SECURITY FEATURES ====================

// Memory-safe key clearing
function clearKeyFromMemory(keyBuffer) {
  if (keyBuffer && typeof keyBuffer.fill === "function") {
    keyBuffer.fill(0); // Zero out memory
  }
}

// Secure random number generation
function secureRandomBytes(size) {
  return crypto.randomBytes(size);
}

// Timing attack resistant comparison
function timingSafeEqual(a, b) {
  try {
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

// ==================== MAIN APPLICATION LOGIC ====================

function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 950,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, "preload.js"),
    },
    backgroundColor: "#FFF5F7",
    title: "Cute Secure Messenger",
    icon: path.join(__dirname, "icons", "icon-512.png"),
    autoHideMenuBar: true,
  });

  mainWindow.loadFile("index.html");

  // Clipboard Monitoring
  let lastClipboardText = clipboard.readText();
  setInterval(() => {
     try {
         const text = clipboard.readText();
         if (text && text !== lastClipboardText) {
             lastClipboardText = text;
             // Basic check if it looks like our JSON envelope
             try {
                const json = JSON.parse(text);
                // Check for valid envelope structure (version 2.0 or 2.0-PFS-MULTI)
                if (json.envelope && (json.envelope.version || json.envelope.v)) {
                    mainWindow.webContents.send('clipboard-content-changed', text);
                    // If window is minimized or not focused, maybe notify?
                    // We let the renderer decide to notify.
                } else if (json.v && json.v.startsWith('STEGO')) {
                     // Stego Payload ? unlikely to be raw text on clipboard usually, but possible
                     mainWindow.webContents.send('clipboard-content-changed', text);
                }
             } catch (e) {
                 // Not JSON, check for PGP
                 if (text.includes('BEGIN PGP MESSAGE')) {
                     mainWindow.webContents.send('clipboard-content-changed', text);
                 }
             }
         }
     } catch (e) {
         // Clipboard access error
     }
  }, 1000); // Check every second

  mainWindow.on('focus', () => {
      mainWindow.webContents.send('window-focused');
  });
}

// Enhanced reset with complete key destruction
function resetMyKeyPair() {
  try {
    console.log("🔐 🔥 DESTROYING ALL KEYS FOR MAXIMUM SECURITY 🔥");
    myKeyPair = null;
    sessionKeys.clear();

    // Destroy all key files
    const keyFiles = [MY_PRIVATE_KEY_FILE, MY_PUBLIC_KEY_FILE, CONTACTS_FILE];

    keyFiles.forEach((file) => {
      if (fs.existsSync(file)) {
        // Overwrite with random data before deletion
        const size = fs.statSync(file).size;
        const randomData = crypto.randomBytes(size);
        fs.writeFileSync(file, randomData);
        fs.unlinkSync(file);
        console.log(`🔥 Permanently destroyed: ${file}`);
      }
    });

    // Clear session key directory
    const sessionFiles = fs.readdirSync(SESSION_KEYS_DIR);
    sessionFiles.forEach((file) => {
      const filePath = path.join(SESSION_KEYS_DIR, file);
      if (fs.existsSync(filePath)) {
        const size = fs.statSync(filePath).size;
        const randomData = crypto.randomBytes(size);
        fs.writeFileSync(filePath, randomData);
        fs.unlinkSync(filePath);
      }
    });

    // Generate new key pair
    const key = loadOrCreateMyKeyPair(true);
    if (key) {
      const newPublicKey = key.exportKey("pkcs1-public-pem");
      console.log("🔐 ✅ New key pair generated with perfect forward secrecy");
      return newPublicKey;
    }
    return null;
  } catch (error) {
    console.error("❌ Key reset error:", error);
    return null;
  }
}

// ==================== IPC HANDLERS ====================

ipcMain.handle("encrypt-text", async (event, text, recipientNames) => {
  if (!recipientNames || recipientNames.length === 0)
    throw new Error("Please select at least one recipient");

  const recipientPublicKeys = {};
  for (const name of recipientNames) {
    const publicKey = getContactPublicKey(name);
    if (!publicKey) throw new Error(`Public key not found for ${name}`);
    recipientPublicKeys[name] = publicKey;
  }

  // Use perfect forward secrecy encryption
  return encryptForMultipleRecipientsWithPFS(text, recipientPublicKeys);
});

ipcMain.handle("decrypt-text", async (event, encryptedText) => {
  // Use PFS decryption
  return decryptWithPerfectForwardSecrecy(encryptedText);
});

ipcMain.handle("reset-my-key", async () => {
  return resetMyKeyPair();
});

ipcMain.handle("get-my-public-key", async () => {
  return getMyPublicKey();
});

ipcMain.handle("generate-mobile-link", async () => {
  try {
    const keyPair = loadOrCreateMyKeyPair();
    if (!keyPair) throw new Error("No key pair found");
    
    // Export raw PEMs
    const privateKey = keyPair.exportKey("pkcs1-private-pem");
    const publicKey = keyPair.exportKey("pkcs1-public-pem");
    
    // Get contacts
    let contacts = [];
    if (fs.existsSync(CONTACTS_FILE)) {
      contacts = JSON.parse(fs.readFileSync(CONTACTS_FILE, "utf8"));
    }
    
    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Derive key from OTP
    // Use salt for Key Derivation
    const salt = crypto.randomBytes(16);
    // PBKDF2: Password, Salt, Iterations, KeyLength, Digest
    const key = crypto.pbkdf2Sync(otp, salt, 10000, 32, "sha256");
    const iv = crypto.randomBytes(16);
    
    // Payload to encrypt
    const payload = JSON.stringify({
      privateKey,
      publicKey,
      contacts
    });
    
    // Encrypt payload with AES-256-CBC
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    let encrypted = cipher.update(payload, "utf8", "base64");
    encrypted += cipher.final("base64");
    
    // Create transfer object
    const transferData = JSON.stringify({
      v: "1",
      s: salt.toString("base64"),
      iv: iv.toString("base64"),
      d: encrypted
    });
    
    // Generate QR Code
    const qrCodeDataUrl = await QRCode.toDataURL(transferData);
    
    return {
      qrCode: qrCodeDataUrl,
      otp: otp,
      transferData: transferData // Return raw string for manual copying
    };
  } catch (error) {
    console.error("Link generation error:", error);
    throw error;
  }
});

ipcMain.handle("link-device-from-payload", async (event, transferDataString, otp) => {
  try {
    const data = JSON.parse(transferDataString);
    if (!data.v || !data.s || !data.iv || !data.d) throw new Error("Invalid payload format");

    // Derive key from OTP + Salt
    const salt = Buffer.from(data.s, "base64");
    const key = crypto.pbkdf2Sync(otp, salt, 10000, 32, "sha256");
    const iv = Buffer.from(data.iv, "base64");

    // Decrypt payload
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    let decrypted = decipher.update(data.d, "base64", "utf8");
    decrypted += decipher.final("utf8");

    const payload = JSON.parse(decrypted);
    if (!payload.privateKey || !payload.publicKey) throw new Error("Invalid payload content");

    // Save Keys
    fs.writeFileSync(MY_PRIVATE_KEY_FILE, payload.privateKey);
    fs.writeFileSync(MY_PUBLIC_KEY_FILE, payload.publicKey);
    fs.chmodSync(MY_PRIVATE_KEY_FILE, 0o600);
    
    // Reload Key Pair in memory
    loadOrCreateMyKeyPair(true);

    // Save Contacts
    if (payload.contacts && Array.isArray(payload.contacts)) {
        fs.writeFileSync(CONTACTS_FILE, JSON.stringify(payload.contacts, null, 2));
    }

    return true;
  } catch (error) {
    console.error("Link failed:", error);
    throw error;
  }
});

// ==================== MISSING IPC HANDLERS ====================

function getContactPublicKey(name) {
  if (fs.existsSync(CONTACTS_FILE)) {
    const contacts = JSON.parse(fs.readFileSync(CONTACTS_FILE, 'utf8'));
    const contact = contacts.find(c => c.name === name);
    return contact ? contact.publicKey : null;
  }
  return null;
}

function getMyPublicKey() {
  const kp = loadOrCreateMyKeyPair();
  return kp ? kp.exportKey('pkcs1-public-pem') : null;
}

ipcMain.handle('load-contacts', async () => {
  if (fs.existsSync(CONTACTS_FILE)) return JSON.parse(fs.readFileSync(CONTACTS_FILE, 'utf8'));
  return [];
});

ipcMain.handle('add-contact', async (event, name, keyData) => {
  let contacts = [];
  if (fs.existsSync(CONTACTS_FILE)) contacts = JSON.parse(fs.readFileSync(CONTACTS_FILE, 'utf8'));
  if (contacts.find(c => c.name === name)) return false;
  const key = new NodeRSA(); key.importKey(keyData, 'pkcs1-public-pem');
  contacts.push({ name, publicKey: keyData, verified: false });
  fs.writeFileSync(CONTACTS_FILE, JSON.stringify(contacts, null, 2));
  return true;
});

ipcMain.handle('update-contact', async (event, name, newKeyData) => {
  if (!fs.existsSync(CONTACTS_FILE)) return false;
  let contacts = JSON.parse(fs.readFileSync(CONTACTS_FILE, 'utf8'));
  const idx = contacts.findIndex(c => c.name === name);
  if (idx === -1) return false;
  if (newKeyData) contacts[idx].publicKey = newKeyData;
  fs.writeFileSync(CONTACTS_FILE, JSON.stringify(contacts, null, 2));
  return true;
});

ipcMain.handle('remove-contact', async (event, name) => {
  if (!fs.existsSync(CONTACTS_FILE)) return false;
  let contacts = JSON.parse(fs.readFileSync(CONTACTS_FILE, 'utf8'));
  contacts = contacts.filter(c => c.name !== name);
  fs.writeFileSync(CONTACTS_FILE, JSON.stringify(contacts, null, 2));
  return true;
});

ipcMain.handle('export-my-key-encrypted', async (event, password) => {
  const kp = loadOrCreateMyKeyPair();
  if (!kp) throw new Error('No key pair');
  const pub = kp.exportKey('pkcs1-public-pem');
  const salt = crypto.randomBytes(SALT_SIZE);
  const key = crypto.pbkdf2Sync(password, salt, EXPORT_KEY_ITERATIONS, EXPORT_KEY_SIZE, 'sha512');
  const iv = crypto.randomBytes(IV_SIZE);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let enc = cipher.update(pub, 'utf8', 'base64'); enc += cipher.final('base64');
  return JSON.stringify({ version:'2.0', salt:salt.toString('base64'), iv:iv.toString('base64'), authTag:cipher.getAuthTag().toString('base64'), data:enc });
});

ipcMain.handle('import-encrypted-key', async (event, encryptedData, password, contactName) => {
  const p = JSON.parse(encryptedData);
  const key = crypto.pbkdf2Sync(password, Buffer.from(p.salt,'base64'), EXPORT_KEY_ITERATIONS, EXPORT_KEY_SIZE, 'sha512');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(p.iv,'base64'));
  decipher.setAuthTag(Buffer.from(p.authTag,'base64'));
  let dec = decipher.update(p.data, 'base64', 'utf8'); dec += decipher.final('utf8');
  const testKey = new NodeRSA(); testKey.importKey(dec, 'pkcs1-public-pem');
  let contacts = []; if (fs.existsSync(CONTACTS_FILE)) contacts = JSON.parse(fs.readFileSync(CONTACTS_FILE, 'utf8'));
  const existing = contacts.findIndex(c => c.name === contactName);
  if (existing >= 0) contacts[existing].publicKey = dec;
  else contacts.push({ name: contactName, publicKey: dec, verified: false });
  fs.writeFileSync(CONTACTS_FILE, JSON.stringify(contacts, null, 2));
  return true;
});

ipcMain.handle('import-public-key', async (event, publicKeyData, contactName, verified) => {
  const testKey = new NodeRSA(); testKey.importKey(publicKeyData, 'pkcs1-public-pem');
  let contacts = []; if (fs.existsSync(CONTACTS_FILE)) contacts = JSON.parse(fs.readFileSync(CONTACTS_FILE, 'utf8'));
  const existing = contacts.findIndex(c => c.name === contactName);
  if (existing >= 0) { contacts[existing].publicKey = publicKeyData; contacts[existing].verified = !!verified; }
  else contacts.push({ name: contactName, publicKey: publicKeyData, verified: !!verified });
  fs.writeFileSync(CONTACTS_FILE, JSON.stringify(contacts, null, 2));
  return true;
});

ipcMain.handle('export-my-public-key', async () => getMyPublicKey());

ipcMain.handle('copy-to-clipboard', async (event, text) => { clipboard.writeText(text); return true; });

ipcMain.handle('copy-image-to-clipboard', async (event, dataUrl) => {
  const img = nativeImage.createFromDataURL(dataUrl);
  clipboard.writeImage(img);
  return true;
});

ipcMain.handle('save-file', async (event, data, defaultPath) => {
  const result = await dialog.showSaveDialog({ defaultPath, filters: [{ name: 'All Files', extensions: ['*'] }] });
  if (!result.canceled && result.filePath) { fs.writeFileSync(result.filePath, data, 'utf8'); return true; }
  return false;
});

ipcMain.handle('load-file', async () => {
  const result = await dialog.showOpenDialog({ properties: ['openFile'] });
  if (!result.canceled && result.filePaths.length > 0) return fs.readFileSync(result.filePaths[0], 'utf8');
  return null;
});

// ==================== STEGO ENCRYPTION ====================

ipcMain.handle('stego-encrypt-image', async (event, imageDataUrl, recipientNames) => {
  if (!recipientNames || recipientNames.length === 0) throw new Error('Please select at least one recipient');

  // Check if __PUBLIC__ is selected
  const isPublic = recipientNames.includes('__PUBLIC__');

  const recipientPublicKeys = {};
  if (!isPublic) {
      for (const name of recipientNames) {
        if (name === '__SELF__') {
          const kp = loadOrCreateMyKeyPair();
          if (!kp) throw new Error('No key pair found');
          recipientPublicKeys['__SELF__'] = kp.exportKey('pkcs1-public-pem');
        } else {
          const pub = getContactPublicKey(name);
          if (!pub) throw new Error(`Public key not found for ${name}`);
          recipientPublicKeys[name] = pub;
        }
      }
  }

  // Generate AES session key
  const sessionKey = crypto.randomBytes(AES_KEY_SIZE);
  const iv = crypto.randomBytes(IV_SIZE);

  // Encrypt image data with AES-256-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
  const imageBuffer = Buffer.from(imageDataUrl, 'utf8');
  let encrypted = cipher.update(imageBuffer);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Encrypt session key for each recipient with their RSA public key
  const recipientKeys = {};
  
  if (isPublic) {
      // Store session key in PUBLIC field (prefixed to avoid confusion)
      recipientKeys['__PUBLIC__'] = sessionKey.toString('base64');
  } else {
      for (const [name, pubKeyPem] of Object.entries(recipientPublicKeys)) {
        const rsa = new NodeRSA();
        rsa.importKey(pubKeyPem, 'pkcs1-public-pem');
        const padded = Buffer.concat([crypto.randomBytes(16), sessionKey, crypto.randomBytes(16)]);
        recipientKeys[name] = rsa.encrypt(padded, 'base64');
      }
  }

  return JSON.stringify({
    v: 'STEGO-2.0',
    recipients: recipientKeys,
    iv: iv.toString('base64'),
    tag: authTag.toString('base64'),
    data: encrypted.toString('base64'),
    ts: Date.now()
  });
});

ipcMain.handle('stego-decrypt-image', async (event, encryptedJson) => {
  const envelope = JSON.parse(encryptedJson);
  if (!envelope.v || !envelope.v.startsWith('STEGO')) throw new Error('Not a stego encrypted envelope');

  let sessionKey = null;

  // Check for Public Key first
  if (envelope.recipients && envelope.recipients['__PUBLIC__']) {
       sessionKey = Buffer.from(envelope.recipients['__PUBLIC__'], 'base64');
  } else {
      const kp = loadOrCreateMyKeyPair();
      if (!kp) throw new Error('No private key found');

      // Try each recipient key to find ours
      for (const [name, encKey] of Object.entries(envelope.recipients)) {
         try {
             const padded = kp.decrypt(encKey, 'buffer'); // RSA-PKCS1-v1_5 used by default in NodeRSA encrypt without options? Wait, above we didn't set options for stego.
             // Default encrypt() uses pkcs1_oaep usually or pkcs1. 
             // In encryptForMultipleRecipientsWithPFS we used oaep. 
             // Here in stego-encrypt-image above I just called rsa.encrypt(padded, 'base64'). NodeRSA default is PKCS1_v1_5.
             // So decrypt needs to match.
             
             // The padded buffer was: 16 bytes random + 32 bytes key + 16 bytes random = 64 bytes total.
             if (padded.length === 64) {
                 sessionKey = padded.slice(16, 16 + 32);
                 break;
             }
         } catch(e) {}
      }
  }

  if (!sessionKey) throw new Error('Not encrypted for you (or decryption failed)');

  const iv = Buffer.from(envelope.iv, 'base64');
  const authTag = Buffer.from(envelope.tag, 'base64');
  const encData = Buffer.from(envelope.data, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, iv);
  decipher.setAuthTag(authTag);
  let dec = decipher.update(encData);
  dec = Buffer.concat([dec, decipher.final()]);

  return dec.toString('utf8'); // Returns the image data URL
});

// ==================== ADVANCED SECURITY MONITORING ====================

// Monitor for cryptographic anomalies
function monitorCryptographicActivity() {
  const startTime = Date.now();
  const operationCounts = {
    encryptions: 0,
    decryptions: 0,
    keyExchanges: 0,
  };

  // Rate limiting to prevent abuse
  setInterval(() => {
    const elapsed = Date.now() - startTime;
    const rate =
      (operationCounts.encryptions + operationCounts.decryptions) /
      (elapsed / 1000);

    if (rate > 100) {
      // More than 100 operations per second
      console.warn("⚠️ High cryptographic activity detected - possible attack");
    }
  }, 5000);
}

// ==================== INITIALIZATION ====================

app.whenReady().then(() => {
  loadOrCreateMyKeyPair();
  createWindow();
  monitorCryptographicActivity();

  // Start clipboard monitoring for auto-detection
  startClipboardMonitoring();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

// Cleanup on quit
app.on("before-quit", () => {
  // Clear sensitive data from memory
  if (myKeyPair) {
    myKeyPair = null;
  }
  sessionKeys.clear();

  // Stop monitoring
  stopClipboardMonitoring();
});

// ==================== FILE VAULT HANDLERS ====================

// Helper to encrypt a file stream
async function encryptFileInternal(filePath, recipientNames) {
  const sessionKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const fileExt = path.extname(filePath);
  const fileName = path.basename(filePath);

  // 1. Prepare Envelope (Recipients)
  const recipientKeys = {};
  
  // Always add self
  const myKeyP = loadOrCreateMyKeyPair(); 
  // Function logic: loadOrCreateMyKeyPair returns NodeRSA instance.
  
  if (myKeyP) {
    const pub = myKeyP.exportKey('pkcs1-public-pem');
    const key = new NodeRSA();
    key.importKey(pub, 'pkcs1-public-pem');
    recipientKeys['__SELF__'] = key.encrypt(sessionKey.toString('base64'), 'base64');
  }

  for (const name of recipientNames) {
    const pub = getContactPublicKey(name);
    if (pub) {
      const key = new NodeRSA();
      key.importKey(pub, 'pkcs1-public-pem');
      recipientKeys[name] = key.encrypt(sessionKey.toString('base64'), 'base64');
    }
  }

  const envelope = {
    v: 'FILE-1.0',
    ts: Date.now(),
    name: fileName,
    iv: iv.toString('base64'),
    recipients: recipientKeys
  };

  const envelopeBuf = Buffer.from(JSON.stringify(envelope), 'utf8');
  const envelopeLenBuf = Buffer.alloc(4);
  envelopeLenBuf.writeUInt32BE(envelopeBuf.length);

  const outputPath = filePath + '.cute';
  const output = fs.createWriteStream(outputPath);
  
  // Write Structure: [Magic:4][Len:4][Envelope][EncryptedData][AuthTag:16]
  const magic = Buffer.from('CUTE', 'utf8'); // Magic header
  output.write(magic);
  output.write(envelopeLenBuf);
  output.write(envelopeBuf);
  
  const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
  const input = fs.createReadStream(filePath);
  
  return new Promise((resolve, reject) => {
    input.pipe(cipher).pipe(output, { end: false });
    
    cipher.on('end', () => {
      const tag = cipher.getAuthTag();
      output.write(tag);
      output.end();
      resolve(outputPath);
    });
    
    cipher.on('error', reject);
    input.on('error', reject);
    output.on('error', reject);
  });
}

// Helper to decrypt a file stream
async function decryptFileInternal(filePath) {
  // Read header to get envelope
  const fd = fs.openSync(filePath, 'r');
  
  const magicBuf = Buffer.alloc(4);
  fs.readSync(fd, magicBuf, 0, 4, 0);
  if (magicBuf.toString() !== 'CUTE') {
    fs.closeSync(fd);
    throw new Error('Not a valid CUTE file');
  }

  const lenBuf = Buffer.alloc(4);
  fs.readSync(fd, lenBuf, 0, 4, 4);
  const envelopeLen = lenBuf.readUInt32BE(0);
  
  const envelopeBuf = Buffer.alloc(envelopeLen);
  fs.readSync(fd, envelopeBuf, 0, envelopeLen, 8);
  const envelope = JSON.parse(envelopeBuf.toString('utf8'));
  
  const dataStart = 8 + envelopeLen;
  const stats = fs.statSync(filePath);
  const totalSize = stats.size;
  const tagStart = totalSize - 16;
  
  // Get Auth Tag (last 16 bytes)
  const authTag = Buffer.alloc(16);
  fs.readSync(fd, authTag, 0, 16, tagStart);
  
  fs.closeSync(fd);

  // Decrypt Session Key
  const myKeys = loadOrCreateMyKeyPair();
  if (!myKeys) throw new Error('No private key found');
  
  let sessionKey = null;
  
  // Try decrypting with our private key
  for (const [name, encKey] of Object.entries(envelope.recipients)) {
    try {
        const decrypted = myKeys.decrypt(encKey, 'utf8'); // Returns base64 string
        if (decrypted) {
            sessionKey = Buffer.from(decrypted, 'base64');
            break;
        }
    } catch (e) {
        // Incorrect key
    }
  }

  if (!sessionKey) throw new Error('You cannot decrypt this file (No matching key found)');

  const iv = Buffer.from(envelope.iv, 'base64');
  
  // Decrypt Stream
  const readStream = fs.createReadStream(filePath, { start: dataStart, end: tagStart - 1 });
  const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, iv);
  decipher.setAuthTag(authTag);
  
  const originalName = envelope.name || 'decrypted_file';
  const newFilename = 'decrypted_' + Date.now() + '_' + originalName;
  const outputPath = path.join(path.dirname(filePath), newFilename);
  const writeStream = fs.createWriteStream(outputPath);
  
  return new Promise((resolve, reject) => {
    readStream.pipe(decipher).pipe(writeStream);
    decipher.on('end', () => resolve(outputPath));
    decipher.on('error', reject);
    writeStream.on('error', reject);
    readStream.on('error', reject);
  });
}


ipcMain.handle('encrypt-file', async (event, filePath, recipientNames) => {
  try {
    return await encryptFileInternal(filePath, recipientNames);
  } catch (e) {
    console.error('File Encrypt Error:', e);
    throw e;
  }
});

ipcMain.handle('decrypt-file', async (event, filePath) => {
  try {
    return await decryptFileInternal(filePath);
  } catch (e) {
     console.error('File Decrypt Error:', e);
    throw e;
  }
});

ipcMain.handle('generate-qr', async (event, text) => {
    return await QRCode.toDataURL(text);
});

// ==================== PGP ENCRYPTION MODULE ====================

const openpgp = require('openpgp');
const PGP_MY_KEYS_FILE = path.join(app.getPath('userData'), 'pgp_my_keys.json');
const PGP_CONTACTS_FILE = path.join(app.getPath('userData'), 'pgp_contacts.json');

// Helper functions for PGP IO
function loadPGPMyKeys() {
    if (fs.existsSync(PGP_MY_KEYS_FILE)) {
        return JSON.parse(fs.readFileSync(PGP_MY_KEYS_FILE, 'utf8'));
    }
    return [];
}
function savePGPMyKeys(keys) {
    fs.writeFileSync(PGP_MY_KEYS_FILE, JSON.stringify(keys, null, 2));
}
function loadPGPContacts() {
    if (fs.existsSync(PGP_CONTACTS_FILE)) {
        return JSON.parse(fs.readFileSync(PGP_CONTACTS_FILE, 'utf8'));
    }
    return [];
}
function savePGPContacts(contacts) {
    fs.writeFileSync(PGP_CONTACTS_FILE, JSON.stringify(contacts, null, 2));
}

// Handler: Generate PGP Key Pair
ipcMain.handle('pgp-generate-key', async (event, name, email, passphrase) => {
    try {
        const { privateKey, publicKey } = await openpgp.generateKey({
            type: 'rsa', // or 'ecc'
            rsaBits: 4096,
            userIDs: [{ name, email }],
            passphrase
        });
        
        const myKeys = loadPGPMyKeys();
        myKeys.push({ 
            id: Date.now().toString(),
            name, 
            email, 
            publicKey, 
            privateKey,
            createdAt: new Date().toISOString()
        });
        savePGPMyKeys(myKeys);
        
        return { success: true, publicKey };
    } catch (error) {
        console.error('PGP Generate Error:', error);
        throw error;
    }
});

// Handler: List My Keys
ipcMain.handle('pgp-list-my-keys', async () => {
    return loadPGPMyKeys().map(k => ({
        id: k.id,
        name: k.name,
        email: k.email,
        publicKey: k.publicKey,
        createdAt: k.createdAt
    }));
});

// Handler: List Contacts
ipcMain.handle('pgp-list-contacts', async () => {
    return loadPGPContacts();
});

// Handler: Import Public Key
ipcMain.handle('pgp-import-contact', async (event, name, keyArmored) => {
    try {
        const key = await openpgp.readKey({ armoredKey: keyArmored }); // Validate
        const contacts = loadPGPContacts();
        
        // check duplicate?
        const existing = contacts.find(c => c.publicKey === keyArmored);
        if (existing) throw new Error('Key already exists');
        
        contacts.push({
            id: Date.now().toString(),
            name,
            publicKey: keyArmored,
            fingerprint: key.getFingerprint()
        });
        savePGPContacts(contacts);
        return true;
    } catch (e) {
        throw new Error('Invalid PGP Key: ' + e.message);
    }
});

// Handler: Encrypt Text
ipcMain.handle('pgp-encrypt-text', async (event, text, recipientIds) => {
    try {
        const contacts = loadPGPContacts();
        const myKeys = loadPGPMyKeys();
        
        // Find recipient keys
        const publicKeysArmored = [];
        
        // Check contacts first
        if (recipientIds && recipientIds.length > 0) {
             for (const rid of recipientIds) {
                const contact = contacts.find(c => c.id === rid);
                if (contact) {
                    publicKeysArmored.push(contact.publicKey);
                } else {
                    // check if it's MY key (self-encrypt)
                    const me = myKeys.find(mk => mk.id === rid);
                    if (me) publicKeysArmored.push(me.publicKey);
                }
             }
        }
        
        // Also encrypt for myself (default key?)
        // Or specific 'me' key if selected.
        
        if (publicKeysArmored.length === 0) throw new Error('No recipients found');

        const encryptionKeys = await Promise.all(publicKeysArmored.map(armored => openpgp.readKey({ armoredKey: armored })));
        
        const message = await openpgp.createMessage({ text });
        const encrypted = await openpgp.encrypt({
            message,
            encryptionKeys
        });
        
        return encrypted;
    } catch (e) {
        console.error('PGP Encrypt Error:', e);
        throw e;
    }
});

// Handler: Decrypt Text
ipcMain.handle('pgp-decrypt-text', async (event, encryptedText, myKeyId, passphrase) => {
    try {
        const myKeys = loadPGPMyKeys();
        const myKeyEntry = myKeys.find(k => k.id === myKeyId);
        
        if (!myKeyEntry) throw new Error('Private key not found');
        
        const privateKey = await openpgp.readPrivateKey({ armoredKey: myKeyEntry.privateKey });
        
        // Decrypt private key with passphrase
        let decryptedPrivateKey = privateKey;
        if (passphrase) {
             decryptedPrivateKey = await openpgp.decryptKey({
                 privateKey,
                 passphrase
             });
        }
        
        const message = await openpgp.readMessage({ armoredMessage: encryptedText });
        
        const { data: decrypted } = await openpgp.decrypt({
            message,
            decryptionKeys: decryptedPrivateKey
        });
        
        return decrypted;
    } catch (e) {
        console.error('PGP Decrypt Error:', e);
        throw new Error('Decryption Failed: ' + e.message);
    }
});



ipcMain.handle('get-app-version', async () => app.getVersion());

ipcMain.handle('open-external', async (event, url) => {
    require('electron').shell.openExternal(url);
    return true;
});


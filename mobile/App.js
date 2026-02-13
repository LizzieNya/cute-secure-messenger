// Shim for Node.js modules
import 'react-native-get-random-values';
global.Buffer = require('buffer').Buffer;

import React, { useState, useEffect } from 'react';
import { StyleSheet, Text, View, TextInput, TouchableOpacity, ScrollView, Alert, Modal, Image, KeyboardAvoidingView, Platform, SafeAreaView, ActivityIndicator, Vibration, Switch, AppState, Linking } from 'react-native';
import { StatusBar } from 'expo-status-bar';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { CameraView, useCameraPermissions } from 'expo-camera';
import * as ImagePicker from 'expo-image-picker';
import * as FileSystem from 'expo-file-system';
import * as Sharing from 'expo-sharing';
import { manipulateAsync, SaveFormat } from 'expo-image-manipulator';
import { decode as decodePng, encode as encodePng } from 'fast-png';
import * as Clipboard from 'expo-clipboard';
import forge from 'node-forge';

const STORAGE_KEYS = {
  PRIVATE_KEY: '@cute_messenger_private_key',
  PUBLIC_KEY: '@cute_messenger_public_key',
  CONTACTS: '@cute_messenger_contacts',
  SETTINGS: '@cute_messenger_settings'
};

// Stego Constants
const BITS_PER_CHANNEL = 2; // 2 bits LSB
const CHANNELS_USED = 4; // RGBA - Must match Desktop for interoperability
const BITS_PER_PIXEL = BITS_PER_CHANNEL * CHANNELS_USED; // 8 bits
const HEADER_BITS = 96; // 32 magic + 32 magic2 + 32 len
const MAGIC_NUMBER = 0xC5E0C5E0;
const MAGIC_NUMBER_2 = 0x57E60827;

const THEMES = {
    pink: { primary: '#FF69B4', secondary: '#FFB6C1', bg: '#FFF5F7', text: '#4B0082', accent: '#8A2BE2' },
    blue: { primary: '#5DADE2', secondary: '#AED6F1', bg: '#EAF2F8', text: '#154360', accent: '#2980B9' },
    mint: { primary: '#58D68D', secondary: '#A9DFBF', bg: '#E8F8F5', text: '#145A32', accent: '#27AE60' },
    lavender: { primary: '#AF7AC5', secondary: '#D2B4DE', bg: '#F5EEF8', text: '#5B2C6F', accent: '#884EA0' },
    peach: { primary: '#FFB347', secondary: '#FFCC80', bg: '#FEF4E8', text: '#BF360C', accent: '#FF8C00' },
    gold: { primary: '#F1C40F', secondary: '#FFF59D', bg: '#F9FBE7', text: '#9A7D0A', accent: '#F39C12' },
    teal: { primary: '#1ABC9C', secondary: '#80CBC4', bg: '#E0F2F1', text: '#004D40', accent: '#16A085' },
    gray: { primary: '#95A5A6', secondary: '#B0BEC5', bg: '#ECEFF1', text: '#263238', accent: '#607D8B' },
    cherry: { primary: '#e74c3c', secondary: '#f1948a', bg: '#fadbd8', text: '#922b21', accent: '#c0392b' },
    coffee: { primary: '#a0522d', secondary: '#edbb99', bg: '#f6ddcc', text: '#6e2c00', accent: '#d35400' },
    ocean: { primary: '#2980b9', secondary: '#aed6f1', bg: '#d6eaf8', text: '#154360', accent: '#3498db' },
    forest: { primary: '#27ae60', secondary: '#a9dfbf', bg: '#d5f5e3', text: '#186a3b', accent: '#2ecc71' },
    sunset: { primary: '#ff6b35', secondary: '#fcb69f', bg: '#fff5ec', text: '#d35400', accent: '#f7418c' },
    grape: { primary: '#7d3c98', secondary: '#c39bd3', bg: '#f4eaf7', text: '#4a235a', accent: '#8e44ad' },
    rose: { primary: '#e91e63', secondary: '#f8bbd0', bg: '#fce4ec', text: '#880e4f', accent: '#c2185b' },
    neon: { primary: '#00e676', secondary: '#b2ebf2', bg: '#e0f7fa', text: '#004d40', accent: '#00bcd4' },
    ice: { primary: '#42a5f5', secondary: '#bbdefb', bg: '#e3f2fd', text: '#0d47a1', accent: '#1565c0' },
    coral: { primary: '#ff7043', secondary: '#ffccbc', bg: '#fbe9e7', text: '#bf360c', accent: '#e64a19' },
    candy: { primary: '#ec407a', secondary: '#f3e5f5', bg: '#fce4ec', text: '#880e4f', accent: '#ab47bc' },
    midnight: { primary: '#5c6bc0', secondary: '#7986cb', bg: '#1a237e', text: '#e8eaf6', accent: '#3949ab' }
};

const FONT_SIZES = {
    small: 14,
    medium: 16,
    large: 18
};

export default function App() {
  const [view, setView] = useState('loading'); // loading, link, main, otp, scan
  const [permission, requestPermission] = useCameraPermissions();
  const [scannedData, setScannedData] = useState(null);
  const [otp, setOtp] = useState('');
  const [isLocked, setIsLocked] = useState(false);
  const appState = React.useRef(AppState.currentState);
  const backgroundTime = React.useRef(0);
  
  // Data
  const [myKeys, setMyKeys] = useState(null);
  const [contacts, setContacts] = useState([]);
  
  // Settings State
  const [settings, setSettings] = useState({
      accentColor: 'pink',
      fontSize: 'medium',
      soundEnabled: true,
      darkMode: false,
      autoLockEnabled: false,
      autoLockMinutes: 5,
      autoRead: true
  });
  const [showSettings, setShowSettings] = useState(false);

  // Messages Tab State
  const [activeTab, setActiveTab] = useState('send');
  const [messageInput, setMessageInput] = useState('');
  const [selectedRecipient, setSelectedRecipient] = useState(null);
  const [decryptInput, setDecryptInput] = useState('');
  const [decryptOutput, setDecryptOutput] = useState('');

  // Stego Tab State
  const [stegoMode, setStegoMode] = useState('hide'); // 'hide' or 'reveal'
  const [decoyUri, setDecoyUri] = useState(null);
  const [secretUri, setSecretUri] = useState(null);
  const [stegoResultUri, setStegoResultUri] = useState(null);
  const [revealInputUri, setRevealInputUri] = useState(null);
  const [revealedResultUri, setRevealedResultUri] = useState(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [stegoStatus, setStegoStatus] = useState('');
  const lastClipboard = React.useRef('');

  useEffect(() => {
    checkKeys();
    loadSettings();
  }, []);

  useEffect(() => {
    const subscription = AppState.addEventListener('change', async nextAppState => {
        if (appState.current.match(/inactive|background/) && nextAppState === 'active') {
             // App returning to foreground
             const now = Date.now();
             if (settings.autoLockEnabled && backgroundTime.current > 0) {
                 const elapsed = (now - backgroundTime.current) / 1000 / 60; // minutes
                 if (elapsed >= settings.autoLockMinutes) {
                     setIsLocked(true);
                 }
             }
             
             // Check clipboard on resume
             if (settings.autoRead) {
                 checkClipboard();
             }

        } else if (nextAppState.match(/inactive|background/)) {
            // App going to background
            backgroundTime.current = Date.now();
        }
        appState.current = nextAppState;
    });

    return () => {
        subscription.remove();
    };
  }, [settings.autoLockEnabled, settings.autoLockMinutes, settings.autoRead]);

  // Periodic Clipboard Check
  useEffect(() => {
    let interval;
    if (settings.autoRead) {
        interval = setInterval(() => {
            if (appState.current === 'active') {
                checkClipboard();
            }
        }, 3000);
    }
    return () => clearInterval(interval);
  }, [settings.autoRead]);

  const checkClipboard = async () => {
      try {
          const content = await Clipboard.getStringAsync();
          if (content && content !== lastClipboard.current) {
              lastClipboard.current = content;
              // Attempt decrypt
              try {
                  const json = JSON.parse(content);
                  if (json.envelope && (json.envelope.version || json.envelope.v)) {
                      // It's a message!
                      setDecryptInput(content);
                      setActiveTab('decrypt');
                      // We can attempt auto-decrypt if we had that logic separated
                      decryptMessage(content); 
                  }
              } catch (e) {
                  // Not our JSON
              }
          }
      } catch (e) {}
  };

  const loadSettings = async () => {
      try {
          const saved = await AsyncStorage.getItem(STORAGE_KEYS.SETTINGS);
          if (saved) setSettings({...settings, ...JSON.parse(saved)});
      } catch (e) { console.warn('Failed to load settings', e); }
  };

  const saveSettings = async (newSettings) => {
      setSettings(newSettings);
      await AsyncStorage.setItem(STORAGE_KEYS.SETTINGS, JSON.stringify(newSettings));
  };

  const checkKeys = async () => {
    try {
      const privateKeyPem = await AsyncStorage.getItem(STORAGE_KEYS.PRIVATE_KEY);
      const publicKeyPem = await AsyncStorage.getItem(STORAGE_KEYS.PUBLIC_KEY);
      const savedContacts = await AsyncStorage.getItem(STORAGE_KEYS.CONTACTS);

      if (privateKeyPem && publicKeyPem) {
        setMyKeys({ private: privateKeyPem, public: publicKeyPem });
        if (savedContacts) {
          setContacts(JSON.parse(savedContacts));
        }
        setView('main');
      } else {
        setView('link');
      }
    } catch (e) {
      console.error(e);
      setView('link');
    }
  };

  const handleBarCodeScanned = ({ data }) => {
    setScannedData(data);
    setView('otp');
  };
  
  const provideFeedback = (type) => {
      if (!settings.soundEnabled) return;
      if (type === 'success') Vibration.vibrate(50);
      else if (type === 'error') Vibration.vibrate([50, 50, 50]);
  };

  const verifyAndLink = async () => {
    if (!scannedData || !otp) {
      Alert.alert('Error', 'Please scan QR code and enter OTP');
      return;
    }

    try {
      const transfer = JSON.parse(scannedData);
      
      const salt = forge.util.decode64(transfer.s);
      const key = forge.pkcs5.pbkdf2(otp, salt, 10000, 32, forge.md.sha256.create());
      const iv = forge.util.decode64(transfer.iv);
      const encrypted = forge.util.decode64(transfer.d);

      // Decrypt: AES-CBC
      const decipher = forge.cipher.createDecipher('AES-CBC', key);
      decipher.start({ iv: iv });
      decipher.update(forge.util.createBuffer(encrypted));
      const result = decipher.finish();

      if (!result) {
        throw new Error('Decryption failed');
      }

      const payload = JSON.parse(decipher.output.toString());
      
      await AsyncStorage.setItem(STORAGE_KEYS.PRIVATE_KEY, payload.privateKey);
      await AsyncStorage.setItem(STORAGE_KEYS.PUBLIC_KEY, payload.publicKey);
      await AsyncStorage.setItem(STORAGE_KEYS.CONTACTS, JSON.stringify(payload.contacts));
      
      setMyKeys({ private: payload.privateKey, public: payload.publicKey });
      setContacts(payload.contacts);
      setView('main');
      provideFeedback('success');
      Alert.alert('Success', 'Phone linked securely! 💖');

    } catch (e) {
      console.error(e);
      provideFeedback('error');
      Alert.alert('Error', 'Decryption failed. Check OTP.');
    }
  };
  
  const handleReset = async () => {
    Alert.alert('Reset App', 'Are you sure you want to unlink? All keys will be removed.', [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Reset', style: 'destructive', onPress: async () => {
          await AsyncStorage.clear();
          setView('link');
          setMyKeys(null);
          setContacts([]);
          setShowSettings(false);
      }}
    ]);
  };

  // --- Text Encryption ---

  const decryptMessage = async () => {
    if (!decryptInput) return;
    try {
      let envelope;
      // Handle both raw JSON and signed envelope formats
      try {
        const parsed = JSON.parse(decryptInput.trim());
        envelope = parsed.envelope || parsed; // Support both wrapped and direct
      } catch (e) { throw new Error('Invalid JSON format'); }

      if (!myKeys || !myKeys.private) throw new Error('No private key');
      
      const privateKey = forge.pki.privateKeyFromPem(myKeys.private);
      
      let encryptedKeyStr = envelope.encryptedKey;
      
      // If it's the multi-recipient format from desktop (v2):
      if (!encryptedKeyStr && envelope.recipients) {
         for (const encK of Object.values(envelope.recipients)) {
             encryptedKeyStr = encK;
             try {
                 const pad = privateKey.decrypt(forge.util.decode64(encryptedKeyStr), 'RSA-OAEP');
                 if (pad) break; 
             } catch(e) {}
         }
      }

      if (!encryptedKeyStr) throw new Error('No encrypted key found for you');
      
      let paddedSessionKey;
      try {
          paddedSessionKey = privateKey.decrypt(forge.util.decode64(encryptedKeyStr), 'RSA-OAEP');
      } catch (e) {
          // Fallback to PCKS1_v1_5 if OAEP fails (legacy compatibility)
          paddedSessionKey = privateKey.decrypt(forge.util.decode64(encryptedKeyStr), 'RSAES-PKCS1-V1_5');
      }

      // Recover session key (32 bytes) offset by 16 bytes (padding)
      const sessionKey = paddedSessionKey.slice(16, 16 + 32);
      
      const iv = forge.util.decode64(envelope.iv);
      const authTag = forge.util.decode64(envelope.authTag || envelope.tag); // Handle both field names
      const encryptedMessage = forge.util.decode64(envelope.encryptedMessage || envelope.data);
      
      const decipher = forge.cipher.createDecipher('AES-GCM', sessionKey);
      decipher.start({ iv: iv, tag: forge.util.createBuffer(authTag) });
      decipher.update(forge.util.createBuffer(encryptedMessage));
      const pass = decipher.finish();
      
      if (pass) {
        setDecryptOutput(decipher.output.toString('utf8'));
        if (settings.autoCopy) {
             Alert.alert('Copied!', 'Decrypted message copied to clipboard.');
             await Clipboard.setStringAsync(decipher.output.toString('utf8'));
        }
        provideFeedback('success');
      } else {
        provideFeedback('error');
        Alert.alert('Error', 'Decryption integrity check failed');
      }
    } catch (e) {
      console.error(e);
      provideFeedback('error');
      Alert.alert('Error', 'Failed to decrypt. Message might not be for you.');
    }
  };
  
  const sendMessage = async () => {
    if (!messageInput || !selectedRecipient) {
        Alert.alert('Error', 'Select a friend and type a message');
        return;
    }
    
    try {
        const friend = contacts.find(c => c.name === selectedRecipient);
        if (!friend) return;
        
        const sessionKey = forge.random.getBytesSync(32);
        const iv = forge.random.getBytesSync(16);
        
        const cipher = forge.cipher.createCipher('AES-GCM', sessionKey);
        cipher.start({ iv: iv });
        cipher.update(forge.util.createBuffer(messageInput, 'utf8'));
        cipher.finish();
        const encryptedMessage = cipher.output.getBytes();
        const authTag = cipher.mode.tag.getBytes();
        
        const publicKey = forge.pki.publicKeyFromPem(friend.publicKey);
        const paddedKey = forge.random.getBytesSync(16) + sessionKey + forge.random.getBytesSync(16);
        const encryptedSessionKey = publicKey.encrypt(paddedKey, 'RSA-OAEP');
        
        const envelope = {
            version: '2.0',
            sessionID: forge.util.bytesToHex(forge.random.getBytesSync(16)),
            timestamp: new Date().toISOString(),
            encryptedKey: forge.util.encode64(encryptedSessionKey),
            iv: forge.util.encode64(iv),
            authTag: forge.util.encode64(authTag),
            encryptedMessage: forge.util.encode64(encryptedMessage),
            nonce: forge.util.bytesToHex(forge.random.getBytesSync(8))
        };
        
        const signedEnvelope = {
            envelope: envelope,
            signature: 'mobile-sig-placeholder',
            senderProof: 'MOBILE-v1.0'
        };
        
        const resultString = JSON.stringify(signedEnvelope);
        setDecryptOutput(resultString); // Reuse decrypt output box for copying result
        Alert.alert('Encrypted!', 'Message encrypted. Copy from the result box below to send.');
        setActiveTab('decrypt'); 
        provideFeedback('success');
    } catch (e) {
        console.error(e);
        provideFeedback('error');
        Alert.alert('Error', 'Encryption failed');
    }
  };

  // --- Steganography Logic ---

  const writeBits = (decoyData, bitOffset, value, numBits) => {
    for (let i = numBits - 1; i >= 0; i--) {
        const bit = (value >> i) & 1;
        const pixelIndex = Math.floor(bitOffset / BITS_PER_PIXEL);
        const channelInPixel = Math.floor((bitOffset % BITS_PER_PIXEL) / BITS_PER_CHANNEL);
        const bitInChannel = bitOffset % BITS_PER_CHANNEL;
        const dataIndex = pixelIndex * 4 + channelInPixel;
        const mask = ~(1 << (BITS_PER_CHANNEL - 1 - bitInChannel));
        decoyData.data[dataIndex] = (decoyData.data[dataIndex] & mask) | (bit << (BITS_PER_CHANNEL - 1 - bitInChannel));
        bitOffset++;
    }
    return bitOffset;
  };

  const readBits = (stegoData, bitOffset, numBits) => {
    let value = 0;
    for (let i = numBits - 1; i >= 0; i--) {
        const pixelIndex = Math.floor(bitOffset / BITS_PER_PIXEL);
        const channelInPixel = Math.floor((bitOffset % BITS_PER_PIXEL) / BITS_PER_CHANNEL);
        const bitInChannel = bitOffset % BITS_PER_CHANNEL;
        const dataIndex = pixelIndex * 4 + channelInPixel;
        const bit = (stegoData.data[dataIndex] >> (BITS_PER_CHANNEL - 1 - bitInChannel)) & 1;
        value |= (bit << i);
        bitOffset++;
    }
    return { value, bitOffset };
  };

  const pickImage = async (setUri) => {
    const result = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ImagePicker.MediaTypeOptions.Images,
      allowsEditing: true, // Allows crop which effectively converts to a stable format (jpg/png) usually
      quality: 1,
      base64: false, // We'll read manually
    });
    if (!result.canceled) {
      setUri(result.assets[0].uri);
    }
  };

  const stegoEncrypt = async (decoyUri, secretUri) => {
    // 1. Ensure Decoy is PNG
    const pngDecoy = await manipulateAsync(decoyUri, [], { format: SaveFormat.PNG });
    
    // 2. Read Decoy Pixels
    const decoyBase64 = await FileSystem.readAsStringAsync(pngDecoy.uri, { encoding: FileSystem.EncodingType.Base64 });
    const decoyBuffer = Buffer.from(decoyBase64, 'base64');
    const decoyData = decodePng(decoyBuffer); // Returns { width, height, data }

    // 3. Read Secret & Encrypt
    const secretBase64 = await FileSystem.readAsStringAsync(secretUri, { encoding: FileSystem.EncodingType.Base64 });
    const secretDataUrl = `data:image/jpeg;base64,${secretBase64}`; // Assume jpeg for generic secret handling or png

    // Encrypt Logic (Hybrid AES + RSA-OAEP) matches Desktop
    const sessionKey = forge.random.getBytesSync(32);
    const iv = forge.random.getBytesSync(16);
    const cipher = forge.cipher.createCipher('AES-GCM', sessionKey);
    cipher.start({ iv: iv });
    cipher.update(forge.util.createBuffer(secretDataUrl, 'utf8'));
    cipher.finish();
    const encryptedBytes = cipher.output.getBytes();
    const authTag = cipher.mode.tag.getBytes();

    // Encrypt Session Key for Recipient (Self or Selected)
    let recipientKeys = {};
    if (selectedRecipient) {
        const friend = contacts.find(c => c.name === selectedRecipient);
        if (friend) {
            const pub = forge.pki.publicKeyFromPem(friend.publicKey);
            const padded = forge.random.getBytesSync(16) + sessionKey + forge.random.getBytesSync(16);
            recipientKeys[friend.name] = forge.util.encode64(pub.encrypt(padded, 'RSA-OAEP'));
        }
    }
 
    const myPub = forge.pki.publicKeyFromPem(myKeys.public);
    const paddedMe = forge.random.getBytesSync(16) + sessionKey + forge.random.getBytesSync(16);
    recipientKeys['__SELF__'] = forge.util.encode64(myPub.encrypt(paddedMe, 'RSA-OAEP'));

    const stegoPayload = JSON.stringify({
        v: 'STEGO-2.0',
        recipients: recipientKeys,
        iv: forge.util.encode64(iv),
        tag: forge.util.encode64(authTag),
        data: forge.util.encode64(encryptedBytes),
        ts: Date.now()
    });

    const payloadBuffer = Buffer.from(stegoPayload, 'utf8');
    
    // 4. Check Capacity
    const capacityBits = (decoyData.width * decoyData.height * BITS_PER_PIXEL) - HEADER_BITS;
    if (payloadBuffer.length * 8 > capacityBits) {
        throw new Error('Secret image is too large for this decoy.');
    }

    // 5. Embed (LSB)
    let bitOffset = 0;
    bitOffset = writeBits(decoyData, bitOffset, MAGIC_NUMBER, 32);
    bitOffset = writeBits(decoyData, bitOffset, MAGIC_NUMBER_2, 32);
    bitOffset = writeBits(decoyData, bitOffset, payloadBuffer.length, 32);

    for (let i = 0; i < payloadBuffer.length; i++) {
        bitOffset = writeBits(decoyData, bitOffset, payloadBuffer[i], 8);
    }

    // 6. Apply Watermark (Pink Box in bottom-right)
    const wmSize = 10;
    const wmMargin = 5;
    const startX = decoyData.width - wmSize - wmMargin;
    const startY = decoyData.height - wmSize - wmMargin;
    
    for(let y = startY; y < startY + wmSize; y++) {
        for(let x = startX; x < startX + wmSize; x++) {
             if(x < 0 || x >= decoyData.width || y < 0 || y >= decoyData.height) continue;
             const idx = (y * decoyData.width + x) * 4;
             // Pink #FF69B4 (255, 105, 180)
             decoyData.data[idx] = 255;
             decoyData.data[idx+1] = 105;
             decoyData.data[idx+2] = 180;
             decoyData.data[idx+3] = 255; 
        }
    }

    // 7. Encode & Save
    const newData = encodePng(decoyData);
    const newBase64 = Buffer.from(newData).toString('base64');
    const filename = `${FileSystem.cacheDirectory}stego_${Date.now()}.png`;
    await FileSystem.writeAsStringAsync(filename, newBase64, { encoding: FileSystem.EncodingType.Base64 });
    
    return filename;
  };

  const stegoDecrypt = async (stegoUri) => {
    // 1. Read & Decode
    const base64 = await FileSystem.readAsStringAsync(stegoUri, { encoding: FileSystem.EncodingType.Base64 });
    const buffer = Buffer.from(base64, 'base64');
    const data = decodePng(buffer);

    // 2. Read Header
    let bitOffset = 0;
    let res = readBits(data, bitOffset, 32); const m1 = res.value; bitOffset = res.bitOffset;
    res = readBits(data, bitOffset, 32); const m2 = res.value; bitOffset = res.bitOffset;

    if (m1 !== MAGIC_NUMBER || m2 !== MAGIC_NUMBER_2) throw new Error('Not a matching stego image');

    res = readBits(data, bitOffset, 32); const len = res.value; bitOffset = res.bitOffset;
    if (len <= 0 || len > 10000000) throw new Error('Invalid data length');

    // 3. Read Payload
    const payloadBuf = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        res = readBits(data, bitOffset, 8);
        payloadBuf[i] = res.value;
        bitOffset = res.bitOffset;
    }

    const jsonStr = Buffer.from(payloadBuf).toString('utf8');
    // Sanitize JSON
    let envelope;
    try {
        envelope = JSON.parse(jsonStr);
    } catch(e) { throw new Error('Failed to parse hidden data'); }

    if (!envelope.v || !envelope.v.startsWith('STEGO')) throw new Error('Invalid stego version');

    // 4. Decrypt Wrapper
    const privateKey = forge.pki.privateKeyFromPem(myKeys.private);
    let sessionKey = null;

    // Try finding our key
    for (const [name, keyStr] of Object.entries(envelope.recipients)) {
        try {
            const padded = privateKey.decrypt(forge.util.decode64(keyStr), 'RSA-OAEP');
            sessionKey = padded.slice(16, 16 + 32);
            break;
        } catch (e) {}
    }

    if (!sessionKey) throw new Error('Not encrypted for you');

    // 5. Decrypt Data
    const iv = forge.util.decode64(envelope.iv);
    const authTag = forge.util.decode64(envelope.tag);
    const encData = forge.util.decode64(envelope.data);

    const decipher = forge.cipher.createDecipher('AES-GCM', sessionKey);
    decipher.start({ iv: iv, tag: forge.util.createBuffer(authTag) });
    decipher.update(forge.util.createBuffer(encData));
    const pass = decipher.finish();

    if (!pass) throw new Error('Integrity check failed');

    // Result is the Data URL of the secret image
    const dataUrl = decipher.output.toString('utf8');
    
    // Write to file for display
    const commaIdx = dataUrl.indexOf(',');
    const secretBase64 = dataUrl.substring(commaIdx + 1);
    const filename = `${FileSystem.cacheDirectory}revealed_${Date.now()}.jpg`; // Assume jpg/png
    await FileSystem.writeAsStringAsync(filename, secretBase64, { encoding: FileSystem.EncodingType.Base64 });
    return filename;
  };

  const handleStegoProcess = async () => {
      setIsProcessing(true);
      setStegoStatus('Processing... this may take a moment 🔮');
      try {
          if (stegoMode === 'hide') {
              if (!decoyUri || !secretUri) return;
              const res = await stegoEncrypt(decoyUri, secretUri);
              setStegoResultUri(res);
              setStegoStatus('Done! Tap image to share/save ✨');
              provideFeedback('success');
          } else {
              // Reveal
              if (!revealInputUri) return;
              const res = await stegoDecrypt(revealInputUri);
              setRevealedResultUri(res);
              setStegoStatus('Revealed! 🤫');
              provideFeedback('success');
          }
      } catch (e) {
          console.error(e);
          Alert.alert('Error', e.message || 'Operation failed');
          setStegoStatus('Failed ❌');
          provideFeedback('error');
      } finally {
          setIsProcessing(false);
      }
  };

  // --- Theme Helpers ---
  const getTheme = () => {
      const base = THEMES[settings.accentColor] || THEMES.pink;
      if (settings.darkMode) {
          return { ...base, bg: '#1a1a2e', text: '#e0e0e0', secondary: '#16213e', headerTitle: '#e0e0e0' };
      }
      return base;
  };
  const getFontSize = () => FONT_SIZES[settings.fontSize] || 16;
  
  const theme = getTheme();
  const fontSize = getFontSize();

  // Dynamic Styles
  const dynamicStyles = {
      container: { backgroundColor: theme.bg },
      header: { backgroundColor: settings.darkMode ? theme.bg : 'white', borderBottomColor: theme.secondary },
      headerTitle: { color: theme.primary },
      headerAction: { color: theme.primary },
      activeTab: { borderBottomColor: theme.primary, backgroundColor: settings.darkMode ? theme.bg : 'white' },
      activeTabText: { color: theme.primary },
      button: { backgroundColor: theme.primary },
      label: { color: theme.text, fontSize: fontSize, fontWeight:'bold' },
      text: { color: theme.text, fontSize: fontSize },
      input: { backgroundColor: settings.darkMode ? '#2c3e50' : 'white', borderColor: theme.secondary, color: theme.text, fontSize: fontSize },
      highlight: { color: theme.primary },
      selectedRecipient: { backgroundColor: theme.primary, borderColor: theme.primary },
      contactCard: { backgroundColor: settings.darkMode ? '#2c3e50' : 'white' }
  };

  // --- Views ---

  // --- Views ---

  if (isLocked) {
      return (
          <View style={[styles.container, {backgroundColor: settings.darkMode ? '#1a1a2e' : theme.bg, alignItems:'center', justifyContent:'center'}]}>
              <StatusBar style={settings.darkMode ? "light" : "dark"} />
              <Text style={{fontSize: 60, marginBottom: 20}}>🔒</Text>
              <Text style={[styles.title, {color: theme.primary}]}>App Locked</Text>
              <Text style={[styles.text, {color: theme.text}]}>Welcome back! Tap to unlock. 💖</Text>
              <TouchableOpacity style={[styles.button, {backgroundColor: theme.primary, width: 200}]} onPress={() => setIsLocked(false)}>
                  <Text style={styles.buttonText}>✨ Unlock</Text>
              </TouchableOpacity>
          </View>
      );
  }

  if (view === 'loading') {
    return (
      <View style={[styles.container, dynamicStyles.container, {alignItems:'center', justifyContent:'center'}]}>
        <ActivityIndicator size="large" color={theme.primary} />
        <Text style={[styles.text, dynamicStyles.text]}>Loading secure vault... 🔐</Text>
      </View>
    );
  }

  if (view === 'link') {
    return (
      <SafeAreaView style={[styles.container, dynamicStyles.container]}>
        <View style={styles.content}>
          <Text style={[styles.title, {color: theme.primary}]}>📱 Link with Desktop</Text>
          <Text style={[styles.text, dynamicStyles.text]}>Scan the QR code from your desktop app to sync keys.</Text>
          <TouchableOpacity style={[styles.button, dynamicStyles.button]} onPress={() => { requestPermission(); setView('scan'); }}>
            <Text style={styles.buttonText}>📷 Scan QR Code</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  if (view === 'scan') {
    if (!permission?.granted) {
      return (
        <View style={styles.container}>
          <Text>No access to camera</Text>
          <TouchableOpacity onPress={requestPermission}><Text>Request Permission</Text></TouchableOpacity>
        </View>
      );
    }
    return (
      <View style={styles.container}>
        <CameraView style={StyleSheet.absoluteFillObject} onBarcodeScanned={handleBarCodeScanned} barcodeScannerSettings={{ barcodeTypes: ["qr"] }} />
        <TouchableOpacity style={styles.closeBtn} onPress={() => setView('link')}>
          <Text style={styles.buttonText}>Cancel</Text>
        </TouchableOpacity>
      </View>
    );
  }

  if (view === 'otp') {
    return (
      <KeyboardAvoidingView behavior={Platform.OS === "ios" ? "padding" : "height"} style={[styles.container, dynamicStyles.container]}>
        <View style={styles.content}>
          <Text style={[styles.title, {color: theme.primary}]}>🔐 Enter OTP</Text>
          <Text style={[styles.text, dynamicStyles.text]}>Enter the 6-digit code from your desktop.</Text>
          <TextInput style={[styles.input, dynamicStyles.input]} placeholder="000000" keyboardType="numeric" value={otp} onChangeText={setOtp} maxLength={6} />
          <TouchableOpacity style={[styles.button, dynamicStyles.button]} onPress={verifyAndLink}><Text style={styles.buttonText}>🔓 Decrypt & Link</Text></TouchableOpacity>
          <TouchableOpacity style={styles.secondaryButton} onPress={() => setView('link')}><Text style={[styles.secondaryButtonText, {color:theme.accent}]}>Cancel</Text></TouchableOpacity>
        </View>
      </KeyboardAvoidingView>
    );
  }

  // NOTE: Main View + Settings Modal
  return (
    <SafeAreaView style={[styles.container, dynamicStyles.container]}>
      <StatusBar style={settings.darkMode ? "light" : "dark"} />
      <View style={[styles.header, dynamicStyles.header]}>
        <Text style={[styles.headerTitle, dynamicStyles.headerTitle]}>🎀 Cute Secure</Text>
        <TouchableOpacity onPress={() => setShowSettings(true)}>
          <Text style={[styles.headerAction, dynamicStyles.headerAction]}>⚙️ Settings</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.tabs}>
        {['send', 'decrypt', 'stego', 'contacts'].map(t => (
            <TouchableOpacity key={t} style={[styles.tab, activeTab === t && dynamicStyles.activeTab]} onPress={() => setActiveTab(t)}>
            <Text style={[styles.tabText, {fontSize: fontSize - 2}, activeTab === t && dynamicStyles.activeTabText]}>{t.charAt(0).toUpperCase() + t.slice(1)}</Text>
            </TouchableOpacity>
        ))}
      </View>

      <ScrollView contentContainerStyle={styles.tabContent}>
        {activeTab === 'send' && (
          <View>
            <Text style={[styles.label, dynamicStyles.label]}>Select Friend:</Text>
            <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.recipientList}>
              {contacts.map(c => (
                <TouchableOpacity key={c.name} style={[styles.recipientChip, {borderColor: theme.secondary}, selectedRecipient === c.name && dynamicStyles.selectedRecipient]} onPress={() => setSelectedRecipient(c.name)}>
                  <Text style={[styles.recipientText, selectedRecipient === c.name && styles.selectedRecipientText]}>{c.name}</Text>
                </TouchableOpacity>
              ))}
            </ScrollView>
            <Text style={[styles.label, dynamicStyles.label]}>Message:</Text>
            <TextInput style={[styles.textArea, dynamicStyles.input]} multiline placeholder="Type a secret message..." value={messageInput} onChangeText={setMessageInput} />
            <TouchableOpacity style={[styles.button, dynamicStyles.button]} onPress={sendMessage}><Text style={styles.buttonText}>✨ Encrypt & Send</Text></TouchableOpacity>
          </View>
        )}

        {activeTab === 'decrypt' && (
          <View>
            <Text style={[styles.label, dynamicStyles.label]}>Paste Encrypted Message:</Text>
            <TextInput style={[styles.textArea, dynamicStyles.input]} multiline placeholder="Paste encrypted text here..." value={decryptInput} onChangeText={setDecryptInput} />
            <TouchableOpacity style={[styles.button, dynamicStyles.button]} onPress={decryptMessage}><Text style={styles.buttonText}>🔓 Decrypt</Text></TouchableOpacity>
            {decryptOutput ? (
              <View style={styles.resultBox}>
                <Text style={[styles.label, dynamicStyles.label]}>Result:</Text>
                <TextInput style={[styles.resultText, {fontSize: fontSize}]} multiline value={decryptOutput} editable={false} />
              </View>
            ) : null}
          </View>
        )}

        {activeTab === 'stego' && (
            <View>
                <View style={{flexDirection:'row', marginBottom: 20}}>
                    <TouchableOpacity style={[styles.chip, stegoMode === 'hide' && [styles.activeChip, {backgroundColor: theme.primary}]]} onPress={()=>setStegoMode('hide')}><Text style={stegoMode==='hide'?{color:'white'}:{color:'#333'}}>Hide 🔒</Text></TouchableOpacity>
                    <TouchableOpacity style={[styles.chip, stegoMode === 'reveal' && [styles.activeChip, {backgroundColor: theme.primary}]]} onPress={()=>setStegoMode('reveal')}><Text style={stegoMode==='reveal'?{color:'white'}:{color:'#333'}}>Reveal 🔓</Text></TouchableOpacity>
                </View>

                {stegoMode === 'hide' ? (
                    <View>
                        <Text style={[styles.label, dynamicStyles.label]}>1. Pick Decoy (Cover Image):</Text>
                        <TouchableOpacity style={[styles.uploadBox, {borderColor: theme.secondary, backgroundColor: theme.secondary + '20'}]} onPress={() => pickImage(setDecoyUri)}>
                            {decoyUri ? <Image source={{uri: decoyUri}} style={styles.previewImage} /> : <Text style={dynamicStyles.text}>🖼️ Tap to pick Decoy</Text>}
                        </TouchableOpacity>

                        <Text style={[styles.label, dynamicStyles.label]}>2. Pick Secret Image:</Text>
                        <TouchableOpacity style={[styles.uploadBox, {borderColor: theme.secondary, backgroundColor: theme.secondary + '20'}]} onPress={() => pickImage(setSecretUri)}>
                            {secretUri ? <Image source={{uri: secretUri}} style={styles.previewImage} /> : <Text style={dynamicStyles.text}>🤫 Tap to pick Secret</Text>}
                        </TouchableOpacity>

                        <Text style={[styles.label, dynamicStyles.label]}>3. Select Recipient (Optional - defaults to self):</Text>
                        <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.recipientList}>
                          {contacts.map(c => (
                            <TouchableOpacity key={c.name} style={[styles.recipientChip, {borderColor: theme.secondary}, selectedRecipient === c.name && dynamicStyles.selectedRecipient]} onPress={() => setSelectedRecipient(c.name)}>
                              <Text style={[styles.recipientText, selectedRecipient === c.name && styles.selectedRecipientText]}>{c.name}</Text>
                            </TouchableOpacity>
                          ))}
                        </ScrollView>

                        <TouchableOpacity style={[styles.button, dynamicStyles.button, isProcessing && {opacity:0.5}]} disabled={isProcessing} onPress={handleStegoProcess}>
                            {isProcessing ? <ActivityIndicator color="white"/> : <Text style={styles.buttonText}>🔮 Encrypt & Hide</Text>}
                        </TouchableOpacity>

                        {stegoStatus ? <Text style={[styles.statusText, dynamicStyles.text]}>{stegoStatus}</Text> : null}

                        {stegoResultUri && (
                            <TouchableOpacity style={[styles.resultImageContainer, {borderColor: theme.primary}]} onPress={() => Sharing.shareAsync(stegoResultUri)}>
                                <Image source={{uri: stegoResultUri}} style={styles.resultImage} />
                                <Text style={[styles.imageOverlayText, {color: theme.primary}]}>Click image to Share/Save 💾</Text>
                            </TouchableOpacity>
                        )}
                    </View>
                ) : (
                    <View>
                        <Text style={[styles.label, dynamicStyles.label]}>Pick Stego Image to Reveal:</Text>
                        <TouchableOpacity style={[styles.uploadBox, {borderColor: theme.secondary, backgroundColor: theme.secondary + '20'}]} onPress={() => pickImage(setRevealInputUri)}>
                            {revealInputUri ? <Image source={{uri: revealInputUri}} style={styles.previewImage} /> : <Text style={dynamicStyles.text}>🕵️ Tap to pick Image</Text>}
                        </TouchableOpacity>

                        <TouchableOpacity style={[styles.button, dynamicStyles.button, isProcessing && {opacity:0.5}]} disabled={isProcessing} onPress={handleStegoProcess}>
                            {isProcessing ? <ActivityIndicator color="white"/> : <Text style={styles.buttonText}>🔓 Reveal Secret</Text>}
                        </TouchableOpacity>

                        {stegoStatus ? <Text style={[styles.statusText, dynamicStyles.text]}>{stegoStatus}</Text> : null}

                        {revealedResultUri && (
                            <TouchableOpacity style={[styles.resultImageContainer, {borderColor: theme.primary}]} onPress={() => Sharing.shareAsync(revealedResultUri)}>
                                <Image source={{uri: revealedResultUri}} style={styles.resultImage} />
                                <Text style={[styles.imageOverlayText, {color: theme.primary}]}>Secret Revealed! Click to Save 💾</Text>
                            </TouchableOpacity>
                        )}
                    </View>
                )}
            </View>
        )}

        {activeTab === 'contacts' && (
          <View>
            {contacts.map(c => (
              <View key={c.name} style={[styles.contactCard, dynamicStyles.contactCard, {borderColor: theme.secondary}]}>
                <View style={[styles.avatar, {backgroundColor: theme.secondary}]}><Text style={styles.avatarText}>{c.name[0]}</Text></View>
                <View>
                  <Text style={[styles.contactName, {color: theme.text}]}>{c.name}</Text>
                  <Text style={[styles.contactStatus, {color: theme.accent}]}>{c.verified ? 'Verified Friend ✅' : 'Unverified'}</Text>
                </View>
              </View>
            ))}
            {contacts.length === 0 && <Text style={[styles.text, dynamicStyles.text]}>No friends synced yet.</Text>}
          </View>
        )}
      </ScrollView>

      {/* Settings Modal */}
      <Modal animationType="slide" transparent={true} visible={showSettings} onRequestClose={() => setShowSettings(false)}>
        <View style={styles.modalOverlay}>
            <View style={[styles.modalContent, {backgroundColor: settings.darkMode ? '#2c3e50' : 'white'}]}>
                <Text style={[styles.title, {color: theme.primary}]}>⚙️ Settings</Text>
                
                <Text style={[styles.label, dynamicStyles.label]}>🎨 Accent Color</Text>
                <View style={styles.settingsRow}>
                    {Object.keys(THEMES).map(color => (
                        <TouchableOpacity key={color} style={[styles.colorOption, {backgroundColor: THEMES[color].primary}, settings.accentColor === color && styles.selectedColorOption]} onPress={() => saveSettings({...settings, accentColor: color})}>
                            {settings.accentColor === color && <Text style={{color:'white'}}>✓</Text>}
                        </TouchableOpacity>
                    ))}
                </View>

                <Text style={[styles.label, dynamicStyles.label]}>🔡 Font Size</Text>
                <View style={styles.settingsRow}>
                    {Object.keys(FONT_SIZES).map(size => (
                        <TouchableOpacity key={size} style={[styles.sizeOption, {borderColor: theme.primary}, settings.fontSize === size && {backgroundColor: theme.primary}]} onPress={() => saveSettings({...settings, fontSize: size})}>
                            <Text style={{color: settings.fontSize === size ? 'white' : theme.primary}}>{size.charAt(0).toUpperCase() + size.slice(1)}</Text>
                        </TouchableOpacity>
                    ))}
                </View>

                <View style={[styles.settingsRow, {justifyContent: 'space-between', alignItems: 'center', marginTop: 10}]}>
                    <Text style={[styles.label, dynamicStyles.label, {marginBottom: 0}]}>🔊 Sound/Haptics</Text>
                    <Switch value={settings.soundEnabled} onValueChange={(val) => saveSettings({...settings, soundEnabled: val})} trackColor={{ true: theme.primary }} />
                </View>

                <View style={[styles.settingsRow, {justifyContent: 'space-between', alignItems: 'center', marginTop: 10}]}>
                    <Text style={[styles.label, dynamicStyles.label, {marginBottom: 0}]}>🌙 Dark Mode</Text>
                    <Switch value={settings.darkMode} onValueChange={(val) => saveSettings({...settings, darkMode: val})} trackColor={{ true: theme.primary }} />
                </View>

                <View style={[styles.settingsRow, {justifyContent: 'space-between', alignItems: 'center', marginTop: 10}]}>
                    <Text style={[styles.label, dynamicStyles.label, {marginBottom: 0}]}>🔒 Auto-Lock (5m)</Text>
                    <Switch value={settings.autoLockEnabled} onValueChange={(val) => saveSettings({...settings, autoLockEnabled: val})} trackColor={{ true: theme.primary }} />
                </View>

                <View style={[styles.settingsRow, {justifyContent: 'space-between', alignItems: 'center', marginTop: 10}]}>
                    <Text style={[styles.label, dynamicStyles.label, {marginBottom: 0}]}>📋 Auto-Copy Decrypt</Text>
                    <Switch value={settings.autoCopy} onValueChange={(val) => saveSettings({...settings, autoCopy: val})} trackColor={{ true: theme.primary }} />
                </View>

                <View style={[styles.settingsRow, {justifyContent: 'space-between', alignItems: 'center', marginTop: 10}]}>
                    <Text style={[styles.label, dynamicStyles.label, {marginBottom: 0}]}>👀 Auto-Read Clipboard</Text>
                    <Switch value={settings.autoRead} onValueChange={(val) => saveSettings({...settings, autoRead: val})} trackColor={{ true: theme.primary }} />
                </View>

                {/* Updates Section */}
                <Text style={[styles.label, dynamicStyles.label, {marginTop: 20}]}>🚀 Application Info</Text>
                <TouchableOpacity style={[styles.button, dynamicStyles.button]} onPress={() => Linking.openURL('https://github.com/LizzieNya/cute-secure-messenger/releases/latest/download/Cute.Secure.Messenger.exe')}>
                    <Text style={styles.buttonText}>💻 Download Windows App</Text>
                </TouchableOpacity>
                 <TouchableOpacity style={[styles.button, {backgroundColor: theme.secondary}]} onPress={() => Linking.openURL('https://lizzienya.github.io/cute-secure-messenger/pwa/')}>
                    <Text style={[styles.buttonText, {color: theme.primary}]}>🌐 Open Web Version</Text>
                </TouchableOpacity>

                <View style={{height: 1, backgroundColor: '#eee', marginVertical: 20}} />

                <TouchableOpacity style={styles.button} onPress={() => setShowSettings(false)}>
                    <Text style={styles.buttonText}>Done</Text>
                </TouchableOpacity>

                 <TouchableOpacity style={[styles.secondaryButton, {marginTop: 10}]} onPress={handleReset}>
                    <Text style={{color: 'red', fontWeight: 'bold'}}>⚠️ Unlink Device</Text>
                </TouchableOpacity>
            </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  content: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 20 },
  title: { fontSize: 24, fontWeight: 'bold', marginBottom: 10 },
  text: { textAlign: 'center', marginBottom: 20 },
  button: { padding: 15, borderRadius: 25, width: '100%', alignItems: 'center', marginBottom: 10, marginTop: 10 },
  buttonText: { color: 'white', fontWeight: 'bold', fontSize: 16 },
  secondaryButton: { padding: 15, alignItems: 'center' },
  secondaryButtonText: { color: '#8A2BE2' },
  input: { backgroundColor: 'white', borderWidth: 2, borderRadius: 10, padding: 15, width: '100%', fontSize: 24, textAlign: 'center', marginBottom: 20 },
  closeBtn: { position: 'absolute', bottom: 40, alignSelf: 'center', backgroundColor: 'rgba(0,0,0,0.5)', padding: 15, borderRadius: 25 },
  header: { padding: 15, paddingTop: 50, borderBottomWidth: 1, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  headerTitle: { fontSize: 20, fontWeight: 'bold' },
  headerAction: { fontWeight: '600' },
  tabs: { flexDirection: 'row', padding: 10, backgroundColor: 'white' },
  tab: { flex: 1, padding: 10, alignItems: 'center', borderBottomWidth: 2, borderBottomColor: 'transparent' },
  tabText: { fontWeight: '600' },
  tabContent: { padding: 20, paddingBottom: 100 },
  label: { marginBottom: 10, marginTop: 10 },
  textArea: { backgroundColor: 'white', borderWidth: 1, borderRadius: 10, padding: 10, height: 100, textAlignVertical: 'top' },
  recipientList: { flexDirection: 'row', marginBottom: 10, height: 50 },
  recipientChip: { padding: 8, paddingHorizontal: 15, backgroundColor: '#E6E6FA', borderRadius: 20, marginRight: 8, borderWidth: 1, justifyContent: 'center' },
  recipientText: { color: '#4B0082' },
  selectedRecipientText: { color: 'white' },
  contactCard: { flexDirection: 'row', backgroundColor: 'white', padding: 15, borderRadius: 12, marginBottom: 10, alignItems: 'center', borderWidth: 1 },
  avatar: { width: 40, height: 40, borderRadius: 20, alignItems: 'center', justifyContent: 'center', marginRight: 15 },
  avatarText: { color: 'white', fontWeight: 'bold', fontSize: 18 },
  contactName: { fontSize: 16, fontWeight: 'bold' },
  contactStatus: { fontSize: 12 },
  resultBox: { marginTop: 20, padding: 10, backgroundColor: '#f0f0f0', borderRadius: 10 },
  resultText: { color: '#333', height: 100, textAlignVertical: 'top' },
  uploadBox: { height: 150, borderRadius: 12, alignItems: 'center', justifyContent: 'center', borderWidth: 1, marginBottom: 10, overflow: 'hidden' },
  previewImage: { width: '100%', height: '100%', resizeMode: 'cover' },
  chip: { padding: 8, paddingHorizontal: 20, backgroundColor: '#eee', borderRadius: 20, marginRight: 10 },
  statusText: { textAlign: 'center', marginTop: 10, fontStyle: 'italic' },
  resultImageContainer: { marginTop: 20, alignItems: 'center', borderWidth: 2, borderRadius: 12 },
  resultImage: { width: 200, height: 200, borderRadius: 10 },
  imageOverlayText: { marginTop: 5, fontWeight: 'bold' },
  modalOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.5)', justifyContent: 'center', alignItems: 'center' },
  modalContent: { width: '85%', padding: 20, borderRadius: 20, elevation: 5 },
  settingsRow: { flexDirection: 'row', gap: 10, flexWrap: 'wrap' },
  colorOption: { width: 40, height: 40, borderRadius: 20, alignItems: 'center', justifyContent: 'center' },
  selectedColorOption: { borderWidth: 3, borderColor: '#333' },
  sizeOption: { padding: 8, borderWidth: 2, borderRadius: 10, minWidth: 70, alignItems: 'center' }
});

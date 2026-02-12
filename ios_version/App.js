// Shim for Node.js modules
import 'react-native-get-random-values';
global.Buffer = require('buffer').Buffer;

import React, { useState, useEffect } from 'react';
import { StyleSheet, Text, View, TextInput, TouchableOpacity, ScrollView, Alert, Modal, Image, KeyboardAvoidingView, Platform, SafeAreaView, ActivityIndicator } from 'react-native';
import { StatusBar } from 'expo-status-bar';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { CameraView, useCameraPermissions } from 'expo-camera';
import * as ImagePicker from 'expo-image-picker';
import * as FileSystem from 'expo-file-system';
import * as Sharing from 'expo-sharing';
import { manipulateAsync, SaveFormat } from 'expo-image-manipulator';
import { decode as decodePng, encode as encodePng } from 'fast-png';
import forge from 'node-forge';
import * as openpgp from 'openpgp';
import { TextEncoder, TextDecoder } from 'fast-text-encoding'; // Polyfill for openpgp

const STORAGE_KEYS = {
  PRIVATE_KEY: '@cute_messenger_private_key',
  PUBLIC_KEY: '@cute_messenger_public_key',
  CONTACTS: '@cute_messenger_contacts'
};

// Stego Constants
const BITS_PER_CHANNEL = 2; // 2 bits LSB
const CHANNELS_USED = 4; // RGBA - Must match Desktop for interoperability
const BITS_PER_PIXEL = BITS_PER_CHANNEL * CHANNELS_USED; // 8 bits
const HEADER_BITS = 96; // 32 magic + 32 magic2 + 32 len
const MAGIC_NUMBER = 0xC5E0C5E0;
const MAGIC_NUMBER_2 = 0x57E60827;

export default function App() {
  const [view, setView] = useState('loading'); // loading, link, main, otp, scan
  const [permission, requestPermission] = useCameraPermissions();
  const [scannedData, setScannedData] = useState(null);
  const [otp, setOtp] = useState('');
  
  // Data
  const [myKeys, setMyKeys] = useState(null);
  const [contacts, setContacts] = useState([]);
  
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

  useEffect(() => {
    checkKeys();
  }, []);

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
      Alert.alert('Success', 'Phone linked securely! 💖');

    } catch (e) {
      console.error(e);
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
      
      // Try to decrypt session key (we might need to try multiple recipients ideally, 
      // but mobile usually assumes 1-to-1 or specific format for now)
      // Desktop sends { recipients: { name: encKey... } } structure for stego, 
      // but standard text messages use a simpler structure in this mobile app version?
      // Actually standard text uses 'encryptedKey' field directly if 1-to-1.
      // Let's support the structure the desktop sends for text messages.
      
      // Adapted from existing mobile logic:
      let encryptedKeyStr = envelope.encryptedKey;
      
      // If it's the multi-recipient format from desktop (v2):
      if (!encryptedKeyStr && envelope.recipients) {
         // Find our key in the list (we don't know our own name easily here locally unless stored,
         // so we try all keys or just fail if not found)
         // For now, let's assume valid key is passed or use first one? No, that's insecure.
         // Real app would know its own identity.
         // Let's just try to decrypt the first one that works?
         for (const encK of Object.values(envelope.recipients)) {
             encryptedKeyStr = encK;
             // Try decrypting this one
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
      } else {
        Alert.alert('Error', 'Decryption integrity check failed');
      }
    } catch (e) {
      console.error(e);
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
    } catch (e) {
        console.error(e);
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
    // For mobile demo, let's encrypt for self OR selected contact if available
    let recipientKeys = {};
    if (selectedRecipient) {
        // Find recipient key
        const friend = contacts.find(c => c.name === selectedRecipient);
        if (friend) {
            const pub = forge.pki.publicKeyFromPem(friend.publicKey);
            const padded = forge.random.getBytesSync(16) + sessionKey + forge.random.getBytesSync(16);
            recipientKeys[friend.name] = forge.util.encode64(pub.encrypt(padded, 'RSA-OAEP'));
        }
    }
    // Always encrypt for self too essentially? Or replace if specific logic.
    // Let's just encrypt for self if no recipient selected, or both.
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

    // 6. Encode & Save
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
          } else {
              // Reveal
              if (!revealInputUri) return;
              const res = await stegoDecrypt(revealInputUri);
              setRevealedResultUri(res);
              setStegoStatus('Revealed! 🤫');
          }
      } catch (e) {
          console.error(e);
          Alert.alert('Error', e.message || 'Operation failed');
          setStegoStatus('Failed ❌');
      } finally {
          setIsProcessing(false);
      }
  };

  // --- Views ---

  if (view === 'loading') {
    return (
      <View style={styles.container}>
        <ActivityIndicator size="large" color="#FF69B4" />
        <Text style={styles.text}>Loading secure vault... 🔐</Text>
      </View>
    );
  }

  if (view === 'link') {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.content}>
          <Text style={styles.title}>📱 Link with Desktop</Text>
          <Text style={styles.text}>Scan the QR code from your desktop app to sync keys.</Text>
          <TouchableOpacity style={styles.button} onPress={() => { requestPermission(); setView('scan'); }}>
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
      <KeyboardAvoidingView behavior={Platform.OS === "ios" ? "padding" : "height"} style={styles.container}>
        <View style={styles.content}>
          <Text style={styles.title}>🔐 Enter OTP</Text>
          <Text style={styles.text}>Enter the 6-digit code from your desktop.</Text>
          <TextInput style={styles.input} placeholder="000000" keyboardType="numeric" value={otp} onChangeText={setOtp} maxLength={6} />
          <TouchableOpacity style={styles.button} onPress={verifyAndLink}><Text style={styles.buttonText}>🔓 Decrypt & Link</Text></TouchableOpacity>
          <TouchableOpacity style={styles.secondaryButton} onPress={() => setView('link')}><Text style={styles.secondaryButtonText}>Cancel</Text></TouchableOpacity>
        </View>
      </KeyboardAvoidingView>
    );
  }

  // NOTE: Main View
  return (
    <SafeAreaView style={styles.container}>
      <StatusBar style="dark" />
      <View style={styles.header}>
        <Text style={styles.headerTitle}>🎀 Cute Secure</Text>
        <TouchableOpacity onPress={handleReset}>
          <Text style={styles.headerAction}>Unlink</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.tabs}>
        <TouchableOpacity style={[styles.tab, activeTab === 'send' && styles.activeTab]} onPress={() => setActiveTab('send')}>
          <Text style={[styles.tabText, activeTab === 'send' && styles.activeTabText]}>Send</Text>
        </TouchableOpacity>
        <TouchableOpacity style={[styles.tab, activeTab === 'decrypt' && styles.activeTab]} onPress={() => setActiveTab('decrypt')}>
          <Text style={[styles.tabText, activeTab === 'decrypt' && styles.activeTabText]}>Decrypt</Text>
        </TouchableOpacity>
        <TouchableOpacity style={[styles.tab, activeTab === 'stego' && styles.activeTab]} onPress={() => setActiveTab('stego')}>
          <Text style={[styles.tabText, activeTab === 'stego' && styles.activeTabText]}>Stego</Text>
        </TouchableOpacity>
        <TouchableOpacity style={[styles.tab, activeTab === 'contacts' && styles.activeTab]} onPress={() => setActiveTab('contacts')}>
          <Text style={[styles.tabText, activeTab === 'contacts' && styles.activeTabText]}>Friends</Text>
        </TouchableOpacity>
      </View>

      <ScrollView contentContainerStyle={styles.tabContent}>
        {activeTab === 'send' && (
          <View>
            <Text style={styles.label}>Select Friend:</Text>
            <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.recipientList}>
              {contacts.map(c => (
                <TouchableOpacity key={c.name} style={[styles.recipientChip, selectedRecipient === c.name && styles.selectedRecipient]} onPress={() => setSelectedRecipient(c.name)}>
                  <Text style={[styles.recipientText, selectedRecipient === c.name && styles.selectedRecipientText]}>{c.name}</Text>
                </TouchableOpacity>
              ))}
            </ScrollView>
            <Text style={styles.label}>Message:</Text>
            <TextInput style={styles.textArea} multiline placeholder="Type a secret message..." value={messageInput} onChangeText={setMessageInput} />
            <TouchableOpacity style={styles.button} onPress={sendMessage}><Text style={styles.buttonText}>✨ Encrypt & Send</Text></TouchableOpacity>
          </View>
        )}

        {activeTab === 'decrypt' && (
          <View>
            <Text style={styles.label}>Paste Encrypted Message:</Text>
            <TextInput style={styles.textArea} multiline placeholder="Paste encrypted text here..." value={decryptInput} onChangeText={setDecryptInput} />
            <TouchableOpacity style={styles.button} onPress={decryptMessage}><Text style={styles.buttonText}>🔓 Decrypt</Text></TouchableOpacity>
            {decryptOutput ? (
              <View style={styles.resultBox}>
                <Text style={styles.label}>Result:</Text>
                <TextInput style={styles.resultText} multiline value={decryptOutput} editable={false} />
              </View>
            ) : null}
          </View>
        )}

        {activeTab === 'stego' && (
            <View>
                <View style={{flexDirection:'row', marginBottom: 20}}>
                    <TouchableOpacity style={[styles.chip, stegoMode === 'hide' && styles.activeChip]} onPress={()=>setStegoMode('hide')}><Text style={stegoMode==='hide'?{color:'white'}:{color:'#333'}}>Hide 🔒</Text></TouchableOpacity>
                    <TouchableOpacity style={[styles.chip, stegoMode === 'reveal' && styles.activeChip]} onPress={()=>setStegoMode('reveal')}><Text style={stegoMode==='reveal'?{color:'white'}:{color:'#333'}}>Reveal 🔓</Text></TouchableOpacity>
                </View>

                {stegoMode === 'hide' ? (
                    <View>
                        <Text style={styles.label}>1. Pick Decoy (Cover Image):</Text>
                        <TouchableOpacity style={styles.uploadBox} onPress={() => pickImage(setDecoyUri)}>
                            {decoyUri ? <Image source={{uri: decoyUri}} style={styles.previewImage} /> : <Text>🖼️ Tap to pick Decoy</Text>}
                        </TouchableOpacity>

                        <Text style={styles.label}>2. Pick Secret Image:</Text>
                        <TouchableOpacity style={styles.uploadBox} onPress={() => pickImage(setSecretUri)}>
                            {secretUri ? <Image source={{uri: secretUri}} style={styles.previewImage} /> : <Text>🤫 Tap to pick Secret</Text>}
                        </TouchableOpacity>

                        <Text style={styles.label}>3. Select Recipient (Optional - defaults to self):</Text>
                        <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.recipientList}>
                          {contacts.map(c => (
                            <TouchableOpacity key={c.name} style={[styles.recipientChip, selectedRecipient === c.name && styles.selectedRecipient]} onPress={() => setSelectedRecipient(c.name)}>
                              <Text style={[styles.recipientText, selectedRecipient === c.name && styles.selectedRecipientText]}>{c.name}</Text>
                            </TouchableOpacity>
                          ))}
                        </ScrollView>

                        <TouchableOpacity style={[styles.button, isProcessing && {opacity:0.5}]} disabled={isProcessing} onPress={handleStegoProcess}>
                            {isProcessing ? <ActivityIndicator color="white"/> : <Text style={styles.buttonText}>🔮 Encrypt & Hide</Text>}
                        </TouchableOpacity>

                        {stegoStatus ? <Text style={styles.statusText}>{stegoStatus}</Text> : null}

                        {stegoResultUri && (
                            <TouchableOpacity style={styles.resultImageContainer} onPress={() => Sharing.shareAsync(stegoResultUri)}>
                                <Image source={{uri: stegoResultUri}} style={styles.resultImage} />
                                <Text style={styles.imageOverlayText}>Click image to Share/Save 💾</Text>
                            </TouchableOpacity>
                        )}
                    </View>
                ) : (
                    <View>
                        <Text style={styles.label}>Pick Stego Image to Reveal:</Text>
                        <TouchableOpacity style={styles.uploadBox} onPress={() => pickImage(setRevealInputUri)}>
                            {revealInputUri ? <Image source={{uri: revealInputUri}} style={styles.previewImage} /> : <Text>🕵️ Tap to pick Image</Text>}
                        </TouchableOpacity>

                        <TouchableOpacity style={[styles.button, isProcessing && {opacity:0.5}]} disabled={isProcessing} onPress={handleStegoProcess}>
                            {isProcessing ? <ActivityIndicator color="white"/> : <Text style={styles.buttonText}>🔓 Reveal Secret</Text>}
                        </TouchableOpacity>

                        {stegoStatus ? <Text style={styles.statusText}>{stegoStatus}</Text> : null}

                        {revealedResultUri && (
                            <TouchableOpacity style={styles.resultImageContainer} onPress={() => Sharing.shareAsync(revealedResultUri)}>
                                <Image source={{uri: revealedResultUri}} style={styles.resultImage} />
                                <Text style={styles.imageOverlayText}>Secret Revealed! Click to Save 💾</Text>
                            </TouchableOpacity>
                        )}
                    </View>
                )}
            </View>
        )}

        {activeTab === 'contacts' && (
          <View>
            {contacts.map(c => (
              <View key={c.name} style={styles.contactCard}>
                <View style={styles.avatar}><Text style={styles.avatarText}>{c.name[0]}</Text></View>
                <View>
                  <Text style={styles.contactName}>{c.name}</Text>
                  <Text style={styles.contactStatus}>{c.verified ? 'Verified Friend ✅' : 'Unverified'}</Text>
                </View>
              </View>
            ))}
            {contacts.length === 0 && <Text style={styles.text}>No friends synced yet.</Text>}
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#FFF5F7' },
  content: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 20 },
  title: { fontSize: 24, fontWeight: 'bold', color: '#FF69B4', marginBottom: 10 },
  text: { fontSize: 16, color: '#8A2BE2', textAlign: 'center', marginBottom: 20 },
  button: { backgroundColor: '#FF69B4', padding: 15, borderRadius: 25, width: '100%', alignItems: 'center', marginBottom: 10, marginTop: 10 },
  buttonText: { color: 'white', fontWeight: 'bold', fontSize: 16 },
  secondaryButton: { padding: 15, alignItems: 'center' },
  secondaryButtonText: { color: '#8A2BE2' },
  input: { backgroundColor: 'white', borderColor: '#DDA0DD', borderWidth: 2, borderRadius: 10, padding: 15, width: '100%', fontSize: 24, textAlign: 'center', marginBottom: 20, color: '#4B0082' },
  closeBtn: { position: 'absolute', bottom: 40, alignSelf: 'center', backgroundColor: 'rgba(0,0,0,0.5)', padding: 15, borderRadius: 25 },
  header: { padding: 15, paddingTop: 50, backgroundColor: 'white', borderBottomWidth: 1, borderBottomColor: '#FFB6C1', flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  headerTitle: { fontSize: 20, fontWeight: 'bold', color: '#FF69B4' },
  headerAction: { color: '#FF69B4', fontWeight: '600' },
  tabs: { flexDirection: 'row', padding: 10, backgroundColor: 'white' },
  tab: { flex: 1, padding: 10, alignItems: 'center', borderBottomWidth: 2, borderBottomColor: 'transparent' },
  activeTab: { borderBottomColor: '#FF69B4' },
  tabText: { color: '#8A2BE2', fontWeight: '600' },
  activeTabText: { color: '#FF69B4' },
  tabContent: { padding: 20, paddingBottom: 100 },
  label: { fontSize: 16, color: '#8A2BE2', fontWeight: '600', marginBottom: 10, marginTop: 10 },
  textArea: { backgroundColor: 'white', borderColor: '#DDA0DD', borderWidth: 1, borderRadius: 10, padding: 10, height: 100, textAlignVertical: 'top', fontSize: 16 },
  recipientList: { flexDirection: 'row', marginBottom: 10, height: 50 },
  recipientChip: { padding: 8, paddingHorizontal: 15, backgroundColor: '#E6E6FA', borderRadius: 20, marginRight: 8, borderWidth: 1, borderColor: '#DDA0DD', justifyContent: 'center' },
  selectedRecipient: { backgroundColor: '#FF69B4', borderColor: '#FF69B4' },
  recipientText: { color: '#4B0082' },
  selectedRecipientText: { color: 'white' },
  contactCard: { flexDirection: 'row', backgroundColor: 'white', padding: 15, borderRadius: 12, marginBottom: 10, alignItems: 'center', borderWidth: 1, borderColor: '#FFB6C1' },
  avatar: { width: 40, height: 40, borderRadius: 20, backgroundColor: '#FFB6C1', alignItems: 'center', justifyContent: 'center', marginRight: 15 },
  avatarText: { color: 'white', fontWeight: 'bold', fontSize: 18 },
  contactName: { fontSize: 16, fontWeight: 'bold', color: '#4B0082' },
  contactStatus: { fontSize: 12, color: '#8A2BE2' },
  resultBox: { marginTop: 20, padding: 10, backgroundColor: '#f0f0f0', borderRadius: 10 },
  resultText: { fontSize: 14, color: '#333', height: 100, textAlignVertical: 'top' },
  uploadBox: { height: 150, backgroundColor: '#E6E6FA', borderRadius: 12, alignItems: 'center', justifyContent: 'center', borderWidth: 1, borderColor: '#DDA0DD', marginBottom: 10, overflow: 'hidden' },
  previewImage: { width: '100%', height: '100%', resizeMode: 'cover' },
  chip: { padding: 8, paddingHorizontal: 20, backgroundColor: '#eee', borderRadius: 20, marginRight: 10 },
  activeChip: { backgroundColor: '#FF69B4' },
  statusText: { textAlign: 'center', color: '#8A2BE2', marginTop: 10, fontStyle: 'italic' },
  resultImageContainer: { marginTop: 20, alignItems: 'center' },
  resultImage: { width: 200, height: 200, borderRadius: 10, borderWidth: 2, borderColor: '#FF69B4' },
  imageOverlayText: { marginTop: 5, color: '#FF69B4', fontWeight: 'bold' }
});

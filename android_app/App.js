// Shim for Node.js modules
import 'react-native-get-random-values';
global.Buffer = require('buffer').Buffer;

import React, { useState, useEffect } from 'react';
import { StyleSheet, Text, View, TextInput, TouchableOpacity, ScrollView, Alert, Modal, Image, KeyboardAvoidingView, Platform, SafeAreaView } from 'react-native';
import { StatusBar } from 'expo-status-bar';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { CameraView, useCameraPermissions } from 'expo-camera';
import forge from 'node-forge';

const STORAGE_KEYS = {
  PRIVATE_KEY: '@cute_messenger_private_key',
  PUBLIC_KEY: '@cute_messenger_public_key',
  CONTACTS: '@cute_messenger_contacts'
};

export default function App() {
  const [view, setView] = useState('loading'); // loading, link, main, otp, scan
  const [permission, requestPermission] = useCameraPermissions();
  const [scannedData, setScannedData] = useState(null);
  const [otp, setOtp] = useState('');
  
  // Data
  const [myKeys, setMyKeys] = useState(null);
  const [contacts, setContacts] = useState([]);
  
  // Messages
  const [activeTab, setActiveTab] = useState('send');
  const [messageInput, setMessageInput] = useState('');
  const [selectedRecipient, setSelectedRecipient] = useState(null);
  const [decryptInput, setDecryptInput] = useState('');
  const [decryptOutput, setDecryptOutput] = useState('');

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

  const decryptMessage = async () => {
    if (!decryptInput) return;
    try {
      const signedEnvelope = JSON.parse(decryptInput.trim());
      const envelope = signedEnvelope.envelope;
      
      const privateKeyPem = await AsyncStorage.getItem(STORAGE_KEYS.PRIVATE_KEY);
      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
      
      const encryptedKey = forge.util.decode64(envelope.encryptedKey);
      const paddedSessionKey = privateKey.decrypt(encryptedKey, 'RSA-OAEP');
      
      const sessionKey = paddedSessionKey.slice(16, 16 + 32);
      
      const iv = forge.util.decode64(envelope.iv);
      const authTag = forge.util.decode64(envelope.authTag);
      const encryptedMessage = forge.util.decode64(envelope.encryptedMessage);
      
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

  if (view === 'loading') {
    return (
      <View style={styles.container}>
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
          
          <TouchableOpacity style={styles.button} onPress={() => {
            requestPermission();
            setView('scan');
          }}>
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
        <CameraView
          style={StyleSheet.absoluteFillObject}
          onBarcodeScanned={handleBarCodeScanned}
          barcodeScannerSettings={{
            barcodeTypes: ["qr"],
          }}
        />
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
          <Text style={styles.text}>Enter the 6-digit code shown on your desktop screen.</Text>
          
          <TextInput
            style={styles.input}
            placeholder="000000"
            keyboardType="numeric"
            value={otp}
            onChangeText={setOtp}
            maxLength={6}
          />
          
          <TouchableOpacity style={styles.button} onPress={verifyAndLink}>
            <Text style={styles.buttonText}>🔓 Decrypt & Link</Text>
          </TouchableOpacity>
          
          <TouchableOpacity style={styles.secondaryButton} onPress={() => setView('link')}>
            <Text style={styles.secondaryButtonText}>Cancel</Text>
          </TouchableOpacity>
        </View>
      </KeyboardAvoidingView>
    );
  }

  // Main View
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
                <TouchableOpacity
                  key={c.name}
                  style={[styles.recipientChip, selectedRecipient === c.name && styles.selectedRecipient]}
                  onPress={() => setSelectedRecipient(c.name)}
                >
                  <Text style={[styles.recipientText, selectedRecipient === c.name && styles.selectedRecipientText]}>{c.name}</Text>
                </TouchableOpacity>
              ))}
            </ScrollView>

            <Text style={styles.label}>Message:</Text>
            <TextInput
              style={styles.textArea}
              multiline
              placeholder="Type a secret message..."
              value={messageInput}
              onChangeText={setMessageInput}
            />

            <TouchableOpacity style={styles.button} onPress={sendMessage}>
              <Text style={styles.buttonText}>✨ Encrypt & Send</Text>
            </TouchableOpacity>
          </View>
        )}

        {activeTab === 'decrypt' && (
          <View>
            <Text style={styles.label}>Paste Encrypted Message:</Text>
            <TextInput
              style={styles.textArea}
              multiline
              placeholder="Paste encrypted text here..."
              value={decryptInput}
              onChangeText={setDecryptInput}
            />
            
            <TouchableOpacity style={styles.button} onPress={decryptMessage}>
              <Text style={styles.buttonText}>🔓 Decrypt</Text>
            </TouchableOpacity>

            {decryptOutput ? (
              <View style={styles.resultBox}>
                <Text style={styles.label}>Result:</Text>
                <TextInput 
                  style={styles.resultText}
                  multiline
                  value={decryptOutput}
                  editable={false}
                />
              </View>
            ) : null}
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
  button: { backgroundColor: '#FF69B4', padding: 15, borderRadius: 25, width: '100%', alignItems: 'center', marginBottom: 10 },
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
  tabContent: { padding: 20 },
  label: { fontSize: 16, color: '#8A2BE2', fontWeight: '600', marginBottom: 10, marginTop: 10 },
  textArea: { backgroundColor: 'white', borderColor: '#DDA0DD', borderWidth: 1, borderRadius: 10, padding: 10, height: 100, textAlignVertical: 'top', fontSize: 16 },
  recipientList: { flexDirection: 'row', marginBottom: 10 },
  recipientChip: { padding: 8, paddingHorizontal: 15, backgroundColor: '#E6E6FA', borderRadius: 20, marginRight: 8, borderWidth: 1, borderColor: '#DDA0DD' },
  selectedRecipient: { backgroundColor: '#FF69B4', borderColor: '#FF69B4' },
  recipientText: { color: '#4B0082' },
  selectedRecipientText: { color: 'white' },
  contactCard: { flexDirection: 'row', backgroundColor: 'white', padding: 15, borderRadius: 12, marginBottom: 10, alignItems: 'center', borderWidth: 1, borderColor: '#FFB6C1' },
  avatar: { width: 40, height: 40, borderRadius: 20, backgroundColor: '#FFB6C1', alignItems: 'center', justifyContent: 'center', marginRight: 15 },
  avatarText: { color: 'white', fontWeight: 'bold', fontSize: 18 },
  contactName: { fontSize: 16, fontWeight: 'bold', color: '#4B0082' },
  contactStatus: { fontSize: 12, color: '#8A2BE2' },
  resultBox: { marginTop: 20, padding: 10, backgroundColor: '#f0f0f0', borderRadius: 10 },
  resultText: { fontSize: 14, color: '#333', height: 100, textAlignVertical: 'top' }
});

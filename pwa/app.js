// ==================== CUTE SECURE MESSENGER PWA v2.0 ====================
// Compatible with Desktop & Mobile (RSA-2048 + AES-256-GCM)
// + Optional PGP for Nerds 🤓

document.addEventListener('DOMContentLoaded', async () => {

    // ==================== STORAGE ====================
    const DB = {
        get(key) { try { return JSON.parse(localStorage.getItem(key)); } catch { return null; } },
        set(key, val) { localStorage.setItem(key, JSON.stringify(val)); },
        remove(key) { localStorage.removeItem(key); }
    };

    // ==================== SERVICE WORKER ====================
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('./sw.js').catch(e => console.warn('SW error:', e));
    }

    // ==================== PWA INSTALL ====================
    let deferredPrompt;
    window.addEventListener('beforeinstallprompt', (e) => {
        e.preventDefault();
        deferredPrompt = e;
        document.getElementById('installBanner').style.display = 'block';
    });
    document.getElementById('installBtn')?.addEventListener('click', async () => {
        if (deferredPrompt) {
            deferredPrompt.prompt();
            await deferredPrompt.userChoice;
            deferredPrompt = null;
            document.getElementById('installBanner').style.display = 'none';
        }
    });

    // ==================== TABS ====================
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            tabPanes.forEach(p => p.classList.remove('active'));
            document.getElementById(`${btn.dataset.tab}-tab`).classList.add('active');
        });
    });

    function showMessage(text, type) {
        const el = document.getElementById('message');
        el.textContent = text;
        el.className = `message ${type}`;
        el.style.display = 'block';
        setTimeout(() => el.style.display = 'none', 3500);
    }

    // ==================== LINKING LOGIC ====================
    let videoStream = null;
    let videoAnimationId = null;
    const linkModal = document.getElementById('linkModal');
    const video = document.getElementById('qrVideo');

    function updateLinkState() {
        const myKeys = DB.get('cute_rsa_keys');
        const unlinked = document.getElementById('unlinkedState');
        const linked = document.getElementById('linkedState');
        
        if (myKeys && myKeys.privateKey) {
            unlinked.style.display = 'none';
            linked.style.display = 'block';
        } else {
            unlinked.style.display = 'block';
            linked.style.display = 'none';
        }
    }

    document.getElementById('startLinkBtn').addEventListener('click', startScanning);
    document.getElementById('closeLinkModal').addEventListener('click', stopScanning);
    document.getElementById('unlinkBtn').addEventListener('click', () => {
        if(confirm('Unlink device? Key data will be removed.')) {
            DB.remove('cute_rsa_keys');
            DB.remove('cute_contacts');
            updateLinkState();
            location.reload();
        }
    });

    async function startScanning() {
        linkModal.style.display = 'block';
        document.getElementById('scanStep').style.display = 'block';
        document.getElementById('otpStep').style.display = 'none';
        
        try {
            videoStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
            video.srcObject = videoStream;
            video.setAttribute('playsinline', true);
            video.play();
            requestAnimationFrame(tick);
        } catch (e) {
            showMessage('Camera access denied! 😢', 'error');
        }
    }

    function stopScanning() {
        if(videoStream) {
            videoStream.getTracks().forEach(t => t.stop());
            videoStream = null;
        }
        if(videoAnimationId) cancelAnimationFrame(videoAnimationId);
        linkModal.style.display = 'none';
    }

    let scannedPayload = null;
    function tick() {
        if (video.readyState === video.HAVE_ENOUGH_DATA && videoStream) {
            const canvas = document.createElement('canvas');
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(imageData.data, imageData.width, imageData.height);
            
            if (code) {
                try {
                    const parsed = JSON.parse(code.data);
                    if(parsed.v && parsed.s && parsed.iv && parsed.d) {
                        scannedPayload = parsed;
                        stopVideoOnly();
                        document.getElementById('scanStep').style.display = 'none';
                        document.getElementById('otpStep').style.display = 'block';
                        document.getElementById('otpInput').focus();
                        return;
                    }
                } catch {}
            }
        }
        if(videoStream) videoAnimationId = requestAnimationFrame(tick);
    }
    
    function stopVideoOnly() {
         if(videoStream) {
            videoStream.getTracks().forEach(t => t.stop());
            videoStream = null;
        }
        if(videoAnimationId) cancelAnimationFrame(videoAnimationId);
    }

    // Verify OTP & Import
    document.getElementById('verifyLinkBtn').addEventListener('click', () => {
        const otp = document.getElementById('otpInput').value.trim();
        if(otp.length !== 6) return showMessage('Enter 6-digit code!', 'error');
        
        try {
            // Decrypt payload: AES-256-CBC with PBKDF2 key
            const salt = forge.util.decode64(scannedPayload.s);
            const iv = forge.util.decode64(scannedPayload.iv);
            const encrypted = forge.util.decode64(scannedPayload.d);
            
            const key = forge.pkcs5.pbkdf2(otp, salt, 10000, 32, forge.md.sha256.create());
            
            const decipher = forge.cipher.createDecipher('AES-CBC', key);
            decipher.start({iv: iv});
            decipher.update(forge.util.createBuffer(encrypted));
            const passed = decipher.finish();
            
            if(!passed) throw new Error('Decryption failed');
            
            const data = JSON.parse(decipher.output.toString());
            
            // Save keys
            DB.set('cute_rsa_keys', {
                privateKey: data.privateKey,
                publicKey: data.publicKey
            });
            
            // Save contacts
            if(data.contacts) {
                DB.set('cute_contacts', data.contacts);
            }
            
            stopScanning();
            updateLinkState();
            loadMainContactsUI();
            showMessage('Device Linked Successfully! 🎉', 'success');
            
        } catch (e) {
            showMessage('Invalid OTP or QR Code! 😢', 'error');
            console.error(e);
        }
    });

    // ==================== RSA + AES ENCRYPTION (Main Tab) ====================

    function getRSAKeys() { return DB.get('cute_rsa_keys'); }
    function getContacts() { return DB.get('cute_contacts') || []; }

    function loadMainContactsUI() {
        const contacts = getContacts();
        const select = document.getElementById('recipientSelect');
        const container = document.getElementById('contactsContainer');
        
        if(!select || !container) return;
        
        select.innerHTML = '';
        container.innerHTML = '';

        contacts.forEach(c => {
            const opt = document.createElement('option');
            opt.value = c.name;
            opt.textContent = c.name;
            select.appendChild(opt);
        });

        // Add self to select if keys exist
        const keys = getRSAKeys();
        if(keys) {
            const opt = document.createElement('option');
            opt.value = 'Note to Self';
            opt.textContent = 'Note to Self 💖';
            select.appendChild(opt);
        }
    }

    document.getElementById('encryptBtn').addEventListener('click', async () => {
        const text = document.getElementById('encryptInput').value;
        const recipientNames = Array.from(document.getElementById('recipientSelect').selectedOptions).map(o => o.value);
        if(!text) return showMessage('Enter a message!', 'error');
        if(recipientNames.length === 0) return showMessage('Select a friend!', 'error');
        
        const myKeys = getRSAKeys();
        if(!myKeys) return showMessage('Please Link Device first! (Or use PGP tab)', 'error');
        
        const results = {};
        const contacts = getContacts();
        
        try {
            // Generate Session Key (32 bytes for AES-256)
            const sessionKey = forge.random.getBytesSync(32);
            const iv = forge.random.getBytesSync(16);
            
            // Encrypt Message with AES-GCM
            const cipher = forge.cipher.createCipher('AES-GCM', sessionKey);
            cipher.start({iv: iv});
            cipher.update(forge.util.createBuffer(text, 'utf8'));
            cipher.finish();
            const encryptedMessage = cipher.output.toString('base64');
            const authTag = cipher.mode.tag.toString('base64');

            // Encrypt Session Key for each recipient
            for(const name of recipientNames) {
                let pubKeyPem;
                if(name === 'Note to Self') pubKeyPem = myKeys.publicKey;
                else {
                    const c = contacts.find(x => x.name === name);
                    if(c) pubKeyPem = c.publicKey || c.key; // Handle different storage formats
                }
                
                if(!pubKeyPem) continue;
                
                const pubKey = forge.pki.publicKeyFromPem(pubKeyPem);
                
                // Add padding to session key (match main.js logic: 16 prefix + key + 16 suffix)
                const prefix = forge.random.getBytesSync(16);
                const suffix = forge.random.getBytesSync(16);
                const paddedKey = prefix + sessionKey + suffix;
                
                // Encrypt session key with RSA (PKCS#1 v1.5 to match NodeRSA default)
                const encryptedKey = forge.util.encode64(pubKey.encrypt(paddedKey));
                
                // Create Envelope
                const envelope = {
                    version: "2.0",
                    sessionID: forge.util.bytesToHex(forge.random.getBytesSync(16)),
                    timestamp: new Date().toISOString(),
                    encryptedKey: encryptedKey,
                    iv: forge.util.encode64(iv),
                    authTag: authTag,
                    encryptedMessage: encryptedMessage,
                    nonce: forge.util.bytesToHex(forge.random.getBytesSync(8))
                };
                
                results[name] = JSON.stringify(envelope);
            }
            
            displayEncryptResults(results);
            showMessage('Encrypted securely! 🔒', 'success');
            
        } catch(e) {
            console.error(e);
            showMessage('Encryption failed: ' + e.message, 'error');
        }
    });

    function displayEncryptResults(results) {
        const container = document.getElementById('multiEncryptResults');
        container.innerHTML = '';
        for (const [name, encrypted] of Object.entries(results)) {
            const div = document.createElement('div');
            div.className = 'result-item';
            div.innerHTML = `
                <div class="result-header">
                    <div class="result-recipient">For ${name}:</div>
                    <button class="result-copy-btn">📋 Copy</button>
                </div>
                <textarea class="result-text" readonly>${encrypted}</textarea>
            `;
            div.querySelector('.result-copy-btn').addEventListener('click', async () => {
                await navigator.clipboard.writeText(encrypted);
                showMessage(`Copied message for ${name}! 📋`, 'success');
            });
            container.appendChild(div);
        }
    }

    // ==================== DECRYPT LOGIC ====================
    document.getElementById('decryptBtn').addEventListener('click', () => {
        const text = document.getElementById('decryptInput').value.trim();
        if(!text) return showMessage('Paste message!', 'error');
        
        const myKeys = getRSAKeys();
        if(!myKeys) return showMessage('Link Device first!', 'error');
        
        try {
            const envelope = JSON.parse(text); // Check if JSON envelope
            
            // Decrypt Session Key
            const privateKey = forge.pki.privateKeyFromPem(myKeys.privateKey);
            const actualEnvelope = envelope.envelope || envelope;
            
            const encryptedKey = forge.util.decode64(actualEnvelope.encryptedKey);
            const decryptedPaddedKey = privateKey.decrypt(encryptedKey, 'RSA-OAEP');
            
            // Extract Session Key (slice 16 bytes prefix, 32 bytes key)
            const sessionKey = decryptedPaddedKey.substring(16, 16 + 32); 
            
            const iv = forge.util.decode64(actualEnvelope.iv);
            const authTag = forge.util.decode64(actualEnvelope.authTag);
            const encryptedMsg = forge.util.decode64(actualEnvelope.encryptedMessage);
            
            const decipher = forge.cipher.createDecipher('AES-GCM', sessionKey);
            decipher.start({
                iv: iv,
                tag: forge.util.createBuffer(authTag) // Auth tag for GCM
            });
            decipher.update(forge.util.createBuffer(encryptedMsg));
            const passed = decipher.finish();
            
            if(passed) {
                document.getElementById('decryptOutput').value = decipher.output.toString('utf8');
                showMessage('Decrypted successfully! 🔓', 'success');
            } else {
                throw new Error('Auth tag verification failed');
            }
            
        } catch (e) {
            console.error(e);
            showMessage('Decryption failed! Is this for you? 🤔', 'error');
        }
    });

    // ==================== PGP (OPTIONAL/NERD) ====================
    
    function getPGPKeys() { return DB.get('cute_pgp_keys') || []; }
    function savePGPKeys(keys) { DB.set('cute_pgp_keys', keys); }
    function getPGPContacts() { return DB.get('cute_pgp_contacts') || []; }

    function refreshPGPKeyList() {
        const list = document.getElementById('pgpKeyList');
        const sel = document.getElementById('pgpRecipientSelect');
        if(!list || !sel) return;
        
        const myKeys = getPGPKeys();
        const contacts = getPGPContacts();
        list.innerHTML = ''; sel.innerHTML = '';

        if (myKeys.length === 0) list.innerHTML = '<p class="pgp-empty">No keys yet.</p>';

        myKeys.forEach(k => {
            const d = document.createElement('div'); d.className = 'pgp-key-item';
            d.innerHTML = `<strong>🔐 ${k.name}</strong><br><small>${k.email}</small>`;
            list.appendChild(d);
            const o = document.createElement('option'); o.value = `my:${k.id}`; o.textContent = `🔐 ${k.name} (Me)`;
            sel.appendChild(o);
        });
        
        // Also PGP contacts here?
    }

    const pgpGenModal = document.getElementById('pgpGenModal');
    document.getElementById('pgpNewKeyBtn')?.addEventListener('click', () => { pgpGenModal.style.display = 'block'; });
    document.getElementById('closePgpGen')?.addEventListener('click', () => { pgpGenModal.style.display = 'none'; });

    document.getElementById('pgpGenerateActionBtn')?.addEventListener('click', async () => {
        const name = document.getElementById('pgpGenName').value;
        const email = document.getElementById('pgpGenEmail').value;
        const pass = document.getElementById('pgpGenPass').value;
        
        if(!name || !email) return showMessage('Name/Email required', 'error');
        
        try {
            const { privateKey, publicKey } = await openpgp.generateKey({
                type: 'ecc', curve: 'curve25519',
                userIDs: [{ name, email }],
                passphrase: pass || undefined
            });
            
            const keys = getPGPKeys();
            keys.push({ id: Date.now().toString(), name, email, publicKey, privateKey, hasPassphrase: !!pass });
            savePGPKeys(keys);
            pgpGenModal.style.display = 'none';
            refreshPGPKeyList();
            showMessage('PGP Key Generated!', 'success');
        } catch(e) { showMessage('Error: ' + e.message, 'error'); }
    });

    document.getElementById('pgpEncryptBtn')?.addEventListener('click', async () => {
        const text = document.getElementById('pgpInput').value;
        if(!text) return;
        try {
            // ... (PGP Encrypt Logic from previous step) ....
            const msg = await openpgp.createMessage({ text });
            // For demo: encrypt with self public key found in selection
            // In real usage, fetch keys from selection
            showMessage('PGP Encrypt Placeholder (Full logic in prev step)', 'info');
        } catch(e) {}
    });

    // ==================== SETTINGS & INIT ====================
    // Theme
    const themeBtn = document.getElementById('toggleThemeBtn');
    if(localStorage.getItem('cute-theme') === 'dark') document.documentElement.classList.add('dark-mode');
    themeBtn?.addEventListener('click', () => {
        const d = document.documentElement.classList.toggle('dark-mode');
        localStorage.setItem('cute-theme', d ? 'dark' : 'light');
    });

    updateLinkState();
    loadMainContactsUI();
    refreshPGPKeyList();
});

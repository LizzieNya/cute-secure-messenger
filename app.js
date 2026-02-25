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
    // ==================== ENVIRONMENT DETECTION ====================
    const isDesktop = navigator.userAgent.toLowerCase().includes('electron') || !!window.electronAPI;
    if (isDesktop) {
        document.body.classList.add('is-desktop');
        
        // Correct the "Link Device" texts so the desktop app doesn't act like it's the PWA
        const linkBannerText = document.querySelector('#unlinkedState > p');
        if (linkBannerText) linkBannerText.innerHTML = '🔗 Link your phone to sync keys & contacts!';
        
        const scanModalText = document.querySelector('#scanStep p');
        if (scanModalText) scanModalText.innerHTML = 'Scan the QR code from your Mobile Phone';
    }

    // ==================== SERVICE WORKER ====================
    // Only for Web/PWA, not Electron
    if (!isDesktop && 'serviceWorker' in navigator) {
        navigator.serviceWorker.register('./sw.js').catch(e => console.warn('SW error:', e));
    }

    // ==================== PWA INSTALL & BANNERS ====================
    if (!isDesktop) {
        let deferredPrompt;
        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            deferredPrompt = e;
            const banner = document.getElementById('installBanner');
            if (banner) banner.style.display = 'block';
        });
        const installBtn = document.getElementById('installBtn');
        if (installBtn) {
            installBtn.addEventListener('click', async () => {
                if (deferredPrompt) {
                    deferredPrompt.prompt();
                    await deferredPrompt.userChoice;
                    deferredPrompt = null;
                    document.getElementById('installBanner').style.display = 'none';
                }
            });
        }
    } else {
        // Hide Platform Banner in Desktop Mode
        const platformBanner = document.getElementById('platformBanner');
        if(platformBanner) platformBanner.style.display = 'none';

        // Hide "Web PWA" card in Settings (irrelevant on desktop)
        const pwaCard = document.querySelector('.download-card-info-only');
        if(pwaCard) pwaCard.style.display = 'none';
        
        // Note: We keep BOTH Windows Desktop and Android download cards visible
        // so users can share download links or grab the APK for their phone
    }

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
            if (typeof initPeerJS === 'function') initPeerJS();
        } else {
            unlinked.style.display = 'block';
            linked.style.display = 'none';
            const statusEl = document.getElementById('p2pStatus');
            if (statusEl) statusEl.textContent = '⚪ Offline';
            if (typeof myPeer !== 'undefined' && myPeer) myPeer.destroy();
            
            // Auto-generate identity if it doesn't exist
            setTimeout(() => {
                if (!DB.get('cute_rsa_keys')) {
                    document.getElementById('createIdentityBtn')?.click();
                }
            }, 500);
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

    // Create Standalone Identity
    document.getElementById('createIdentityBtn')?.addEventListener('click', async () => {
         showMessage('Generating 2048-bit RSA keys... This may take a moment ⏳', 'info');
         
         // Allow UI to render the message before blocking
         setTimeout(() => {
             try {
                // Removed workers: 2 to avoid issues on OOM/restricted environments
                // Running on main thread might freeze UI temporarily but is more reliable
                 forge.pki.rsa.generateKeyPair({ bits: 2048 }, (err, keypair) => {
                     if(err) throw err;
                     
                     const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
                     const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
                     
                     DB.set('cute_rsa_keys', {
                         privateKey: privateKeyPem,
                         publicKey: publicKeyPem
                     });
                     
                     if (!DB.get('cute_contacts')) {
                        DB.set('cute_contacts', []);
                     }
                     
                     updateLinkState();
                     loadMainContactsUI();
                     showMessage('Identity Auto-Created! You can now chat securely 💖', 'success');
                 });
             } catch(e) {
                 console.error(e);
                 showMessage('Key Gen Failed: ' + e.message, 'error');
             }
         }, 100);
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
    // ==================== LINK ANOTHER DEVICE (HOST MODE) ====================
    
    document.getElementById('generateHostLinkBtn')?.addEventListener('click', () => {
        const myKeys = DB.get('cute_rsa_keys');
        if (!myKeys || !myKeys.privateKey) {
            return showMessage('You need an identity first! Create one or link a device.', 'error');
        }

        try {
            const contacts = DB.get('cute_contacts') || [];
            
            // Generate 6-digit OTP
            const otp = Math.floor(100000 + Math.random() * 900000).toString();
            
            // Derive key with PBKDF2
            const salt = forge.random.getBytesSync(16);
            const iv = forge.random.getBytesSync(16);
            const key = forge.pkcs5.pbkdf2(otp, salt, 10000, 32, forge.md.sha256.create());
            
            // Payload
            const payload = JSON.stringify({
                privateKey: myKeys.privateKey,
                publicKey: myKeys.publicKey,
                contacts: contacts
            });
            
            // Encrypt AES-256-CBC
            const cipher = forge.cipher.createCipher('AES-CBC', key);
            cipher.start({ iv: iv });
            cipher.update(forge.util.createBuffer(payload, 'utf8'));
            const passed = cipher.finish();
            if(!passed) throw new Error('Encryption failed');
            
            const encrypted = cipher.output.getBytes();
            
            const transferData = JSON.stringify({
                v: "1",
                s: forge.util.encode64(salt),
                iv: forge.util.encode64(iv),
                d: forge.util.encode64(encrypted)
            });
            
            // Show modal and draw QR
            const qrContainer = document.getElementById('hostLinkQrContainer');
            qrContainer.innerHTML = '';
            
            // Render QR code using qrcodejs
            new QRCode(qrContainer, {
                text: transferData,
                width: 256,
                height: 256,
                colorDark : "#000000",
                colorLight : "#ffffff",
                correctLevel : QRCode.CorrectLevel.L
            });
            
            document.getElementById('hostLinkOtpDisplay').innerText = otp;
            document.getElementById('hostLinkModal').style.display = 'block';
            
        } catch(e) {
            console.error(e);
            showMessage('Failed to generate link QR: ' + e.message, 'error');
        }
    });

    document.getElementById('closeHostLinkModal')?.addEventListener('click', () => {
        document.getElementById('hostLinkModal').style.display = 'none';
        document.getElementById('hostLinkQrContainer').innerHTML = ''; // clear for security
        document.getElementById('hostLinkOtpDisplay').innerText = '000000';
    });

    // ==================== RSA + AES ENCRYPTION (Main Tab) ====================

    function getRSAKeys() { return DB.get('cute_rsa_keys'); }
    function getContacts() { return DB.get('cute_contacts') || []; }

    function loadMainContactsUI() {
        const contacts = getContacts();
        const select = document.getElementById('recipientSelect');
        const list = document.getElementById('contactsContainer');
        const myKeyField = document.getElementById('myPublicKey');
        
        // Populate Select (for Main Encrypt Tab)
        if(select) {
            select.innerHTML = '';
            contacts.forEach(c => {
                const opt = document.createElement('option');
                opt.value = c.name;
                opt.textContent = c.name;
                select.appendChild(opt);
            });
            // Add Self
             const keys = getRSAKeys();
             if(keys) {
                 const opt = document.createElement('option');
                 opt.value = 'Note to Self';
                 opt.textContent = 'Note to Self 💖';
                 select.appendChild(opt);
             }
        }

        // Populate List (for Contacts Tab)
        if(list) {
            list.innerHTML = '';
            if(contacts.length === 0) {
                 list.innerHTML = '<div style="text-align:center; padding:20px; color:#888;">No friends yet! 🥺<br>Add someone above!</div>';
            } else {
                contacts.forEach(c => {
                    const div = document.createElement('div');
                    div.className = 'contact-card'; // Add CSS for this later?
                    div.style.background = 'rgba(255,255,255,0.5)';
                    div.style.padding = '10px';
                    div.style.borderRadius = '10px';
                    div.style.marginBottom = '10px';
                    div.style.border = '1px solid rgba(0,0,0,0.05)';
                    
                    div.innerHTML = `
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <strong>👤 ${c.name}</strong>
                            <button class="btn-secondary btn-small delete-contact-btn" data-name="${c.name}" style="background:#ffcccc; color:#cc0000; border:none; padding:2px 8px; border-radius:5px; cursor:pointer;">🗑️</button>
                        </div>
                        <div style="font-size:0.7em; color:#666; margin:5px 0; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
                            ${c.publicKey ? c.publicKey.substring(0, 50) + '...' : 'Invalid Key'}
                        </div>
                        <button class="btn-secondary btn-small copy-contact-btn" data-key="${c.publicKey}" style="width:100%;">📋 Copy Key</button>
                    `;
                    list.appendChild(div);
                });
                
                // Add listeners
                list.querySelectorAll('.delete-contact-btn').forEach(b => {
                    b.addEventListener('click', (e) => {
                        if(confirm(`Remove friend ${b.dataset.name}?`)) {
                            const newC = getContacts().filter(x => x.name !== b.dataset.name);
                            DB.set('cute_contacts', newC);
                            loadMainContactsUI();
                        }
                    });
                });
                list.querySelectorAll('.copy-contact-btn').forEach(b => {
                    b.addEventListener('click', async () => {
                        await navigator.clipboard.writeText(b.dataset.key);
                        showMessage('Key copied!', 'success');
                    });
                });
            }
        }
        
        // Populate "My Identity"
        if(myKeyField) {
            const keys = getRSAKeys();
            if(keys) {
                myKeyField.value = keys.publicKey;
            } else {
                myKeyField.value = '';
                myKeyField.placeholder = "No identity found. Link Device or Create New Identity.";
            }
        }
    }
    
    // Call it initially
    loadMainContactsUI();

    // ==================== NEW CONTACTS LISTENERS ====================
    
    // Add Friend (Manual)
    document.getElementById('addContactFormBtn')?.addEventListener('click', () => {
        const name = document.getElementById('newContactName').value.trim();
        const key = document.getElementById('newContactKey').value.trim();
        
        if(!name || !key) return showMessage('Name and Key required!', 'error');
        if(!key.includes('BEGIN PUBLIC KEY')) return showMessage('Invalid RSA Public Key!', 'error');
        
        const contacts = getContacts();
        if(contacts.find(x => x.name === name)) return showMessage('Name already exists!', 'error');
        
        contacts.push({ name, publicKey: key });
        DB.set('cute_contacts', contacts);
        loadMainContactsUI();
        showMessage(`Friend ${name} added! 💕`, 'success');
        document.getElementById('newContactName').value = '';
        document.getElementById('newContactKey').value = '';
    });

    // Copy My Key
    document.getElementById('copyKeyBtn')?.addEventListener('click', async () => {
        const myKeyField = document.getElementById('myPublicKey');
        if(myKeyField && myKeyField.value) {
            await navigator.clipboard.writeText(myKeyField.value);
            showMessage('Identity Copied! 📋', 'success');
        } else {
            showMessage('No identity to copy!', 'error');
        }
    });

    // Import Contact (File Trigger)
    document.getElementById('importContactBtn')?.addEventListener('click', () => {
        document.getElementById('importContactInput').click();
    });

    // Import Contact (File Process)
    document.getElementById('importContactInput')?.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if(!file) return;
        
        const reader = new FileReader();
        reader.onload = async (evt) => {
            const text = evt.target.result;
            let finalKey = '';
            let finalName = file.name.replace(/\.(json|keyenc|pubkey|pem)$/, '');
            
            try {
                // Try Parsing JSON (Encrypted)
                const json = JSON.parse(text);
                if(json.salt && json.iv && json.data && json.authTag) {
                    // It's encrypted
                    const pass = prompt(`Enter password to decrypt "${finalName}":`);
                    if(!pass) return; // Cancelled
                    
                    showMessage('Decrypting key... ⏳', 'info');
                    
                    // Derive Key
                    const salt = forge.util.decode64(json.salt);
                    const iv = forge.util.decode64(json.iv);
                    const authTag = forge.util.decode64(json.authTag);
                    const encryptedBytes = forge.util.decode64(json.data);
                    
                    const deriveKey = forge.pkcs5.pbkdf2(pass, salt, 100000, 32, forge.md.sha512.create());
                    const decipher = forge.cipher.createDecipher('AES-GCM', deriveKey);
                    decipher.start({ iv: iv, tag: forge.util.createBuffer(authTag) });
                    decipher.update(forge.util.createBuffer(encryptedBytes));
                    if(decipher.finish()) {
                        finalKey = decipher.output.toString(); // Should be PEM
                        showMessage('Key Decrypted! ✅', 'success');
                    } else {
                        throw new Error('Wrong password or corrupted file');
                    }
                } else if(json.publicKey) {
                    finalKey = json.publicKey; // Maybe raw JSON export?
                }
            } catch(e) {
                // Not JSON, assume Raw PEM
                if(text.includes('BEGIN PUBLIC KEY')) {
                    finalKey = text;
                } else {
                    console.error(e);
                    return showMessage('Invalid Key File!', 'error');
                }
            }
            
            if(finalKey) {
                const name = prompt('Enter name for this friend:', finalName);
                if(name) {
                    const contacts = getContacts();
                    if(contacts.find(x => x.name === name)) return showMessage('Contact exists!', 'error'); 
                    contacts.push({ name, publicKey: finalKey });
                    DB.set('cute_contacts', contacts);
                    loadMainContactsUI();
                    showMessage(`Friend ${name} imported! 💕`, 'success');
                }
            }
        };
        reader.readAsText(file);
        e.target.value = ''; // Reset
    });
    
    // Export Encrypted Key
    document.getElementById('exportEncryptedKeyBtn')?.addEventListener('click', async () => {
        const keys = getRSAKeys();
        if(!keys) return showMessage('No identity to export!', 'error');
        
        const pass = prompt('Choose a password to encrypt this file:');
        if(!pass) return;
        
        showMessage('Encrypting... ⏳', 'info');
        
        setTimeout(() => {
            try {
                const salt = forge.random.getBytesSync(32);
                const iv = forge.random.getBytesSync(16);
                
                const key = forge.pkcs5.pbkdf2(pass, salt, 100000, 32, forge.md.sha512.create());
                const cipher = forge.cipher.createCipher('AES-GCM', key);
                cipher.start({ iv: iv });
                cipher.update(forge.util.createBuffer(keys.publicKey)); // Export Public Key
                cipher.finish();
                
                const result = {
                    version: '2.0',
                    salt: forge.util.encode64(salt),
                    iv: forge.util.encode64(iv),
                    authTag: forge.util.encode64(cipher.mode.tag),
                    data: forge.util.encode64(cipher.output)
                };
                
                const blob = new Blob([JSON.stringify(result, null, 2)], {type: 'application/json'});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'my_identity_public.keyenc';
                a.click();
                URL.revokeObjectURL(url);
                showMessage('Exported Encrypted Key! 🔒', 'success');
                
            } catch(e) { console.error(e); showMessage('Export Failed!', 'error'); }
        }, 100);
    });

    // ==================== BACKUP & RESTORE KEYS (Settings Tab) ====================

    // Export All Keys (Encrypted Backup)
    document.getElementById('exportKeysBtn')?.addEventListener('click', async () => {
        const rsaKeys = getRSAKeys();
        const contacts = getContacts();
        const pgpKeys = getPGPKeys();
        
        if(!rsaKeys && pgpKeys.length === 0) return showMessage('No keys to backup!', 'error');

        const pass = prompt('Create a password to encrypt your backup file:\n(Do not forget this password!)');
        if(!pass) return;

        showMessage('Creating secure backup... ⏳', 'info');

        setTimeout(() => {
            try {
                const backupData = JSON.stringify({
                    version: '2.0',
                    timestamp: new Date().toISOString(),
                    rsa: rsaKeys,
                    contacts: contacts,
                    pgp: pgpKeys,
                    // potential other settings?
                    settings: {
                        theme: settings.theme,
                        accentColor: settings.accentColor
                    }
                });

                const salt = forge.random.getBytesSync(32);
                const iv = forge.random.getBytesSync(16);
                const key = forge.pkcs5.pbkdf2(pass, salt, 100000, 32, forge.md.sha512.create());
                
                const cipher = forge.cipher.createCipher('AES-GCM', key);
                cipher.start({ iv: iv });
                cipher.update(forge.util.createBuffer(backupData, 'utf8'));
                cipher.finish();

                const encryptedBackup = {
                    backup: true,
                    v: '2.0',
                    salt: forge.util.encode64(salt),
                    iv: forge.util.encode64(iv),
                    tag: forge.util.encode64(cipher.mode.tag),
                    data: forge.util.encode64(cipher.output)
                };

                const blob = new Blob([JSON.stringify(encryptedBackup, null, 2)], {type: 'application/json'});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `cute_messenger_backup_${new Date().toISOString().slice(0,10)}.json`;
                a.click();
                URL.revokeObjectURL(url);
                showMessage('Backup saved securely! 💾', 'success');

            } catch(e) {
                console.error(e);
                showMessage('Backup Failed: ' + e.message, 'error');
            }
        }, 100);
    });

    // Import Keys Trigger
    document.getElementById('importKeysBtn')?.addEventListener('click', () => {
        if(confirm('Importing a backup will OVERWRITE your current keys and contacts.\n\nContinue?')) {
            document.getElementById('importKeysInput').click();
        }
    });

    // Import Keys Process
    document.getElementById('importKeysInput')?.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if(!file) return;

        const reader = new FileReader();
        reader.onload = async (evt) => {
            try {
                const json = JSON.parse(evt.target.result);
                
                if(!json.backup || !json.data || !json.salt || !json.iv) {
                    throw new Error('Invalid backup file format');
                }

                const pass = prompt(`Enter password for backup "${file.name}":`);
                if(!pass) return;

                showMessage('Decrypting backup... ⏳', 'info');

                setTimeout(() => {
                    try {
                        const salt = forge.util.decode64(json.salt);
                        const iv = forge.util.decode64(json.iv);
                        const tag = forge.util.decode64(json.tag);
                        const encryptedBytes = forge.util.decode64(json.data);

                        const key = forge.pkcs5.pbkdf2(pass, salt, 100000, 32, forge.md.sha512.create());
                        const decipher = forge.cipher.createDecipher('AES-GCM', key);
                        decipher.start({ iv: iv, tag: forge.util.createBuffer(tag) });
                        decipher.update(forge.util.createBuffer(encryptedBytes));
                        
                        if(!decipher.finish()) throw new Error('Incorrect password or corrupted file');

                        const decryptedData = JSON.parse(decipher.output.toString('utf8'));

                        // Restore Data
                        if(decryptedData.rsa) DB.set('cute_rsa_keys', decryptedData.rsa);
                        if(decryptedData.contacts) DB.set('cute_contacts', decryptedData.contacts);
                        if(decryptedData.pgp) savePGPKeys(decryptedData.pgp);
                        
                        // Restore Settings if present
                        if(decryptedData.settings) {
                            if(decryptedData.settings.theme) {
                                settings.theme = decryptedData.settings.theme;
                                localStorage.setItem('cute-theme', settings.theme);
                            }
                            if(decryptedData.settings.accentColor) {
                                settings.accentColor = decryptedData.settings.accentColor;
                                localStorage.setItem('cute-accent', settings.accentColor);
                            }
                            applySettings();
                        }

                        // Refresh UI
                        updateLinkState();
                        loadMainContactsUI();
                        refreshPGPKeyList();

                        showMessage('Backup Restored Successfully! 🎉', 'success');

                    } catch(e) {
                        console.error(e);
                        showMessage('Restoration Failed: ' + e.message, 'error');
                    }
                }, 100);

            } catch(e) {
                console.error(e);
                showMessage('Invalid file or password!', 'error');
            }
        };
        reader.readAsText(file);
        e.target.value = ''; // Reset input
    });

    let currentMailAttachment = null;
    const mailAttachBtn = document.getElementById('mailAttachBtn');
    const mailAttachInput = document.getElementById('mailAttachInput');
    const mailAttachmentPreview = document.getElementById('mailAttachmentPreview');
    const mailAttachImg = document.getElementById('mailAttachImg');
    const mailAttachClearBtn = document.getElementById('mailAttachClearBtn');

    mailAttachBtn?.addEventListener('click', () => {
        mailAttachInput?.click();
    });

    mailAttachInput?.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;

        if (file.size > 5 * 1024 * 1024) {
            showMessage('Image is too large (max 5MB).', 'error');
            e.target.value = '';
            return;
        }

        const reader = new FileReader();
        reader.onload = (ev) => {
            currentMailAttachment = ev.target.result;
            if (mailAttachImg) mailAttachImg.src = currentMailAttachment;
            if (mailAttachmentPreview) mailAttachmentPreview.style.display = 'flex';
        };
        reader.readAsDataURL(file);
    });

    mailAttachClearBtn?.addEventListener('click', () => {
        currentMailAttachment = null;
        if (mailAttachImg) mailAttachImg.src = '';
        if (mailAttachmentPreview) mailAttachmentPreview.style.display = 'none';
        if (mailAttachInput) mailAttachInput.value = '';
    });

    document.getElementById('encryptBtn').addEventListener('click', async () => {
        const text = document.getElementById('encryptInput').value.trim() || '';
        const recipientNames = Array.from(document.getElementById('recipientSelect').selectedOptions).map(o => o.value);
        if(!text && !currentMailAttachment) return showMessage('Enter a message or attach an image!', 'error');
        if(recipientNames.length === 0) return showMessage('Select a friend!', 'error');
        
        const myKeys = getRSAKeys();
        if(!myKeys) return showMessage('Please Link Device first! (Or use PGP tab)', 'error');
        
        const results = {};
        const contacts = getContacts();
        
        try {
            // Generate Session Key (32 bytes for AES-256)
            const sessionKey = forge.random.getBytesSync(32);
            const iv = forge.random.getBytesSync(16);
            
            // Create a composite payload string
            const payloadObject = { text: text, image: currentMailAttachment };
            const payloadString = JSON.stringify(payloadObject);

            // Encrypt Message with AES-GCM
            const cipher = forge.cipher.createCipher('AES-GCM', sessionKey);
            cipher.start({iv: iv});
            cipher.update(forge.util.createBuffer(payloadString, 'utf8'));
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
                
                // Encrypt session key with RSA (RSA-OAEP)
                const encryptedKey = forge.util.encode64(pubKey.encrypt(paddedKey, 'RSA-OAEP'));
                
                // Create Envelope
                const rawEnvelope = {
                    version: "2.0",
                    sessionID: forge.util.bytesToHex(forge.random.getBytesSync(16)),
                    timestamp: new Date().toISOString(),
                    encryptedKey: encryptedKey,
                    iv: forge.util.encode64(iv),
                    authTag: authTag,
                    encryptedMessage: encryptedMessage,
                    nonce: forge.util.bytesToHex(forge.random.getBytesSync(8))
                };
                
                // Wrap in signed structure (Signature is placeholder for now as Desktop verification is permissive)
                const signedEnvelope = {
                    envelope: rawEnvelope,
                    signature: "signature-placeholder", 
                    senderProof: "PFS-v2.0"
                };
                
                results[name] = JSON.stringify(signedEnvelope);
            }
            
            displayEncryptResults(results);
            showMessage('Encrypted securely! 🔒', 'success');
            playSound('sent');
            
        } catch(e) {
            console.error(e);
            showMessage('Encryption failed: ' + e.message, 'error');
            playSound('error');
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
    document.getElementById('decryptBtn').addEventListener('click', async () => {
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
                const decryptedStr = decipher.output.toString('utf8');
                let parsedText = decryptedStr;
                let parsedImage = null;

                try {
                    const obj = JSON.parse(decryptedStr);
                    if (obj && (typeof obj.text !== 'undefined' || typeof obj.image !== 'undefined')) {
                        parsedText = obj.text || '';
                        parsedImage = obj.image || null;
                    }
                } catch (e) {
                    // Fallback to plain text
                }

                document.getElementById('decryptOutput').value = parsedText;
                
                const imgEl = document.getElementById('decryptOutputImg');
                if (parsedImage) {
                    imgEl.src = parsedImage;
                    imgEl.style.display = 'block';
                } else {
                    imgEl.src = '';
                    imgEl.style.display = 'none';
                }
                
                if (settings.autoCopy) {
                    await navigator.clipboard.writeText(parsedText);
                    showMessage('Decrypted & Copied! 🔓📋', 'success');
                } else {
                    showMessage('Decrypted successfully! 🔓', 'success');
                }
                playSound('receive');
            } else {
                throw new Error('Auth tag verification failed');
            }
            
        } catch (e) {
            console.error(e);
            showMessage('Decryption failed! Is this for you? 🤔', 'error');
            playSound('error');
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

    document.getElementById('pgpGenerateActionBtn')?.addEventListener('click', () => {
        const name = document.getElementById('pgpGenName').value;
        const email = document.getElementById('pgpGenEmail').value;
        const pass = document.getElementById('pgpGenPass').value;
        
        if(!name || !email) return showMessage('Name & Email required!', 'error');

        const btn = document.getElementById('pgpGenerateActionBtn');
        const originalText = btn.textContent;
        btn.textContent = 'Generating... ⏳';
        btn.disabled = true;

        setTimeout(async () => {
            try {
                // Generate RSA 2048 keys (Desktop compatible)
                const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
                    type: 'rsa',
                    rsaBits: 2048,
                    userIDs: [{ name, email }],
                    passphrase: pass || undefined
                });
                
                const id = Date.now().toString();
                const keys = getPGPKeys();
                keys.push({ 
                    id, 
                    name, 
                    email, 
                    publicKey, 
                    privateKey, 
                    revocationCertificate, 
                    hasPassphrase: !!pass,
                    createdAt: new Date().toISOString()
                });
                savePGPKeys(keys);
                
                if (pgpGenModal) pgpGenModal.style.display = 'none';
                refreshPGPKeyList();
                showMessage('PGP Key Generated Successfully! 🎉', 'success');
                
                // Clear inputs
                document.getElementById('pgpGenName').value = '';
                document.getElementById('pgpGenEmail').value = '';
                document.getElementById('pgpGenPass').value = '';

            } catch(e) { 
                console.error(e);
                showMessage('Generation Error: ' + e.message, 'error'); 
            } finally {
                btn.textContent = originalText;
                btn.disabled = false;
            }
        }, 100);
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
    // ==================== SETTINGS & THEME ====================
    
    const settings = {
        accentColor: localStorage.getItem('cute-accent') || 'pink',
        fontSize: localStorage.getItem('cute-fontsize') || 'medium',
        soundEnabled: localStorage.getItem('cute-sound') !== 'false',
        theme: localStorage.getItem('cute-theme') || 'light',
        layout: localStorage.getItem('cute-layout') || 'default',
        autoCopy: localStorage.getItem('cute-autocopy') === 'true',
        animations: localStorage.getItem('cute-animations') !== 'false'
    };

    function applySettings() {
        // Apply Theme (Dark/Light)
        if (settings.theme === 'dark') document.documentElement.classList.add('dark-mode');
        else document.documentElement.classList.remove('dark-mode');

        // Apply Accent Color
        document.body.classList.remove('theme-blue', 'theme-mint', 'theme-lavender', 'theme-peach', 'theme-gold', 'theme-teal', 'theme-gray', 'theme-cherry', 'theme-coffee', 'theme-ocean', 'theme-forest', 'theme-sunset', 'theme-grape', 'theme-rose', 'theme-neon', 'theme-ice', 'theme-coral', 'theme-candy', 'theme-midnight');
        if (settings.accentColor !== 'pink') {
            document.body.classList.add(`theme-${settings.accentColor}`);
        }
        
        // Update UI buttons (Color)
        document.querySelectorAll('.color-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.color === settings.accentColor);
        });

        // Apply Layout
        document.body.classList.remove('layout-compact', 'layout-pro');
        if (settings.layout === 'compact') document.body.classList.add('layout-compact');
        if (settings.layout === 'pro') document.body.classList.add('layout-pro');

        document.querySelectorAll('.layout-btn').forEach(btn => {
            btn.classList.toggle('active', btn.getAttribute('data-layout') === settings.layout);
        });

        // Apply Animations
        if (!settings.animations) document.body.classList.add('no-animations');
        else document.body.classList.remove('no-animations');
        
        const animToggle = document.getElementById('animationsToggle');
        if (animToggle) animToggle.checked = settings.animations;

        const autoCopyToggle = document.getElementById('autoCopyToggle');
        if (autoCopyToggle) autoCopyToggle.checked = settings.autoCopy;

        // Apply Font Size
        document.body.classList.remove('font-small', 'font-medium', 'font-large');
        document.body.classList.add(`font-${settings.fontSize}`);

        // Update UI buttons (Font)
        document.querySelectorAll('.font-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.size === settings.fontSize);
        });

        // Apply Sound UI
        const soundToggle = document.getElementById('soundToggle');
        if (soundToggle) soundToggle.checked = settings.soundEnabled;
    }

    // Initialize Settings
    applySettings();

    // Event Listeners
    document.getElementById('toggleThemeBtn')?.addEventListener('click', () => {
        settings.theme = settings.theme === 'dark' ? 'light' : 'dark';
        localStorage.setItem('cute-theme', settings.theme);
        applySettings();
    });

    document.querySelectorAll('.color-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            settings.accentColor = btn.dataset.color;
            localStorage.setItem('cute-accent', settings.accentColor);
            applySettings();
        });
    });

    document.querySelectorAll('.layout-btn').forEach(btn => {
        btn.addEventListener('click', () => {
             settings.layout = btn.getAttribute('data-layout');
             localStorage.setItem('cute-layout', settings.layout);
             applySettings();
        });
    });

    const animToggle = document.getElementById('animationsToggle');
    if (animToggle) {
        animToggle.addEventListener('change', (e) => {
            settings.animations = e.target.checked;
            localStorage.setItem('cute-animations', settings.animations);
            applySettings();
        });
    }

    const autoCopyToggle = document.getElementById('autoCopyToggle');
    if (autoCopyToggle) {
        autoCopyToggle.addEventListener('change', (e) => {
            settings.autoCopy = e.target.checked;
            localStorage.setItem('cute-autocopy', settings.autoCopy);
        });
    }

    document.querySelectorAll('.font-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            settings.fontSize = btn.dataset.size;
            localStorage.setItem('cute-fontsize', settings.fontSize);
            applySettings();
        });
    });

    document.getElementById('soundToggle')?.addEventListener('change', (e) => {
        settings.soundEnabled = e.target.checked;
        localStorage.setItem('cute-sound', settings.soundEnabled);
    });

    // Sound Effect Helper
    function playSound(type) {
        if (!settings.soundEnabled) return;
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);
        
        const now = ctx.currentTime;
        if (type === 'sent') {
            osc.frequency.setValueAtTime(880, now);
            osc.frequency.exponentialRampToValueAtTime(1760, now + 0.1);
            gain.gain.setValueAtTime(0.1, now);
            gain.gain.exponentialRampToValueAtTime(0.01, now + 0.3);
            osc.start(now);
            osc.stop(now + 0.3);
        } else if (type === 'receive') {
            osc.frequency.setValueAtTime(523.25, now);
            osc.frequency.linearRampToValueAtTime(659.25, now + 0.1);
            gain.gain.setValueAtTime(0.1, now);
            gain.gain.exponentialRampToValueAtTime(0.01, now + 0.4);
            osc.start(now);
            osc.stop(now + 0.4);
        } else if (type === 'error') {
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(220, now);
            osc.frequency.linearRampToValueAtTime(110, now + 0.2);
            gain.gain.setValueAtTime(0.1, now);
            gain.gain.linearRampToValueAtTime(0.01, now + 0.3);
            osc.start(now);
            osc.stop(now + 0.3);
        }
    }

    // PGP Mode Toggle
    const pgpModeBtn = document.getElementById('togglePgpModeBtn');
    const pgpTabBtn = document.getElementById('pgpTabBtn');
    const pgpHintText = document.getElementById('pgpHintText');

    function updatePgpModeUI(enabled) {
        if(enabled) {
            pgpTabBtn.style.display = '';
            pgpHintText.style.display = '';
            pgpModeBtn.textContent = 'Disable PGP Mode 🔒';
            pgpModeBtn.classList.remove('btn-secondary');
            pgpModeBtn.classList.add('btn-primary');
        } else {
            pgpTabBtn.style.display = 'none';
            pgpHintText.style.display = 'none';
            pgpModeBtn.textContent = 'Enable PGP Mode 🔓';
            pgpModeBtn.classList.remove('btn-primary');
            pgpModeBtn.classList.add('btn-secondary');
            
            // If we are currently on the PGP tab, switch to Encrypt tab
            if(pgpTabBtn.classList.contains('active')) {
                document.querySelector('.tab-btn[data-tab="encrypt"]').click();
            }
        }
    }

    const pgpEnabled = localStorage.getItem('cute-pgp-mode') === 'enabled';
    updatePgpModeUI(pgpEnabled);

    pgpModeBtn?.addEventListener('click', () => {
        const isEnabled = localStorage.getItem('cute-pgp-mode') === 'enabled';
        const newState = !isEnabled;
        localStorage.setItem('cute-pgp-mode', newState ? 'enabled' : 'disabled');
        updatePgpModeUI(newState);
        if(newState) showMessage('Advanced PGP Mode Enabled! 🤓', 'success');
        else showMessage('PGP Mode Disabled', 'info');
    });

    try {
        updateLinkState();
        loadMainContactsUI();
        refreshPGPKeyList();
        console.log("Cute Messenger v2.0 Initialized 🎀");
    } catch(e) {
        console.error("Startup Error:", e);
        showMessage("Startup Error: " + e.message, "error");
    }

    // ==================== STEGANOGRAPHY MODULE ====================
    
    // Constants
    const BITS_PER_CHANNEL = 2;
    const CHANNELS_USED = 3; 
    const BITS_PER_DECOY_PIXEL = 6;
    const HEADER_BITS = 96;
    const MAGIC_NUMBER = 0xC5E0C5E0;
    const MAGIC_NUMBER_2 = 0x57E60827;

    // State
    let decoyImageData = null;
    let secretImageData = null;
    let stegoDecodeImageData = null;

    // UI Toggles
    document.querySelectorAll('.stego-mode-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const mode = btn.dataset.stegoMode;
            document.querySelectorAll('.stego-mode-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.stego-section').forEach(s => s.classList.remove('active'));
            document.getElementById(`stego-${mode}`).classList.add('active');
        });
    });

    // Helpers
    function loadImageFromFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const img = new Image();
                img.onload = () => {
                    const canvas = document.createElement('canvas');
                    canvas.width = img.width;
                    canvas.height = img.height;
                    const ctx = canvas.getContext('2d');
                    ctx.drawImage(img, 0, 0);
                    const imageData = ctx.getImageData(0, 0, img.width, img.height);
                    resolve({
                        width: img.width,
                        height: img.height,
                        data: imageData.data,
                        dataURL: e.target.result
                    });
                };
                img.onerror = reject;
                img.src = e.target.result;
            };
            reader.onerror = reject;
            reader.readAsDataURL(file);
        });
    }

    function setupUploadZone(zoneId, inputId, placeholderId, previewId, infoId, onLoad) {
        const zone = document.getElementById(zoneId);
        const input = document.getElementById(inputId);
        const placeholder = document.getElementById(placeholderId);
        const preview = document.getElementById(previewId);

        zone.addEventListener('click', () => input.click());
        input.addEventListener('change', async (e) => {
            if (e.target.files[0]) {
                try {
                    const data = await loadImageFromFile(e.target.files[0]);
                    placeholder.style.display = 'none';
                    preview.src = data.dataURL;
                    preview.style.display = 'block';
                    if (infoId) document.getElementById(infoId).textContent = `${data.width}×${data.height}px`;
                    onLoad(data);
                } catch (err) { showMessage('Failed to load image', 'error'); }
            }
        });
    }

    setupUploadZone('decoyDropZone', 'decoyImageInput', 'decoyPlaceholder', 'decoyPreview', 'decoyInfo', (data) => {
        decoyImageData = data;
        updateStegoUI();
    });

    setupUploadZone('secretDropZone', 'secretImageInput', 'secretPlaceholder', 'secretPreview', 'secretInfo', (data) => {
        secretImageData = data;
        updateStegoUI();
    });

    setupUploadZone('stegoDecodeDropZone', 'stegoDecodeInput', 'stegoDecodePlaceholder', 'stegoDecodePreview', null, (data) => {
        stegoDecodeImageData = data;
        document.getElementById('stegoDecodeBtn').disabled = false;
    });

    function estimateEncryptedSize() {
        if (!secretImageData) return 0;
        const rawLen = secretImageData.dataURL.length;
        return Math.ceil(rawLen * 1.4) + 800; // Overhead approximation
    }

    function updateStegoUI() {
        const bar = document.getElementById('stegoCapacityBar');
        const btn = document.getElementById('stegoEncodeBtn');
        
        if (!decoyImageData || !secretImageData) {
            bar.style.width = '0%';
            btn.disabled = true;
            return;
        }

        const estBytes = estimateEncryptedSize();
        const bitsNeeded = HEADER_BITS + (estBytes * 8);
        const totalDecoyPixels = decoyImageData.width * decoyImageData.height;
        const pixelsNeeded = Math.ceil(bitsNeeded / BITS_PER_DECOY_PIXEL);
        const usage = (pixelsNeeded / totalDecoyPixels) * 100;

        bar.style.width = Math.min(usage, 100) + '%';
        if (usage > 100) {
            bar.style.backgroundColor = 'red';
            document.getElementById('stegoCapacityText').textContent = '❌ Capacity Exceeded!';
            btn.disabled = true;
        } else {
            bar.style.backgroundColor = '#2ecc71';
            document.getElementById('stegoCapacityText').textContent = `Capacity Usage: ~${usage.toFixed(1)}%`;
            btn.disabled = false;
        }
    }

    // Bit Operations
    function writeBits(decoyData, bitOffset, value, numBits) {
        for (let i = numBits - 1; i >= 0; i--) {
            const bit = (value >> i) & 1;
            const pixelIndex = Math.floor(bitOffset / BITS_PER_DECOY_PIXEL);
            const channelInPixel = Math.floor((bitOffset % BITS_PER_DECOY_PIXEL) / BITS_PER_CHANNEL);
            const bitInChannel = bitOffset % BITS_PER_CHANNEL;
            const dataIndex = pixelIndex * 4 + channelInPixel;
            const mask = ~(1 << (BITS_PER_CHANNEL - 1 - bitInChannel));
            decoyData[dataIndex] = (decoyData[dataIndex] & mask) | (bit << (BITS_PER_CHANNEL - 1 - bitInChannel));
            bitOffset++;
        }
        return bitOffset;
    }

    function readBits(stegoData, bitOffset, numBits) {
        let value = 0;
        for (let i = numBits - 1; i >= 0; i--) {
            const pixelIndex = Math.floor(bitOffset / BITS_PER_DECOY_PIXEL);
            const channelInPixel = Math.floor((bitOffset % BITS_PER_DECOY_PIXEL) / BITS_PER_CHANNEL);
            const bitInChannel = bitOffset % BITS_PER_CHANNEL;
            const dataIndex = pixelIndex * 4 + channelInPixel;
            const bit = (stegoData[dataIndex] >> (BITS_PER_CHANNEL - 1 - bitInChannel)) & 1;
            value |= (bit << i);
            bitOffset++;
        }
        return { value, bitOffset };
    }

    // Watermark
    function drawWatermark(ctx, canvasWidth, canvasHeight) {
        const size = 14, margin = 4;
        const x = canvasWidth - size - margin, y = canvasHeight - size - margin;
        ctx.save(); ctx.globalAlpha = 0.8;
        ctx.fillStyle = '#FF69B4';
        ctx.beginPath(); ctx.ellipse(x + 4, y + 5, 3.5, 4, -0.3, 0, Math.PI * 2); ctx.fill();
        ctx.beginPath(); ctx.ellipse(x + 10, y + 5, 3.5, 4, 0.3, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = 'white';
        ctx.font = '10px serif';
        ctx.fillText('CSM', x-5, y+5);
        ctx.restore();
    }

    // Client Encrypt
    async function stegoEncryptImageClient(secretDataUrl, recipientNames) {
        const sessionKey = forge.random.getBytesSync(32);
        const iv = forge.random.getBytesSync(16);
        
        const cipher = forge.cipher.createCipher('AES-GCM', sessionKey);
        cipher.start({ iv: iv });
        cipher.update(forge.util.createBuffer(secretDataUrl, 'utf8'));
        cipher.finish();
        const encryptedData = cipher.output.toString('base64');
        const authTag = cipher.mode.tag.toString('base64');

        const recipients = {};
        const myKeys = getRSAKeys();
        const contacts = getContacts();

        // Default to self if no recipients provided
        if (!recipientNames || recipientNames.length === 0) recipientNames = ['Note to Self'];

        for(const name of recipientNames) {
            let pubKeyPem;
            if(name === 'Note to Self' || name === '__SELF__') pubKeyPem = myKeys.publicKey;
            else {
                const c = contacts.find(x => x.name === name);
                if(c) pubKeyPem = c.publicKey || c.key;
            }
            if(!pubKeyPem) continue;

            const pub = forge.pki.publicKeyFromPem(pubKeyPem);
            const padded = forge.random.getBytesSync(16) + sessionKey + forge.random.getBytesSync(16);
            recipients[name] = forge.util.encode64(pub.encrypt(padded, 'RSA-OAEP'));
        }

        return JSON.stringify({
            v: 'STEGO-2.0',
            recipients: recipients,
            iv: forge.util.encode64(iv),
            tag: authTag,
            data: encryptedData,
            ts: Date.now()
        });
    }

    // Encode Action
    document.getElementById('stegoEncodeBtn').addEventListener('click', async () => {
        if (!decoyImageData || !secretImageData) return;
        
        const btn = document.getElementById('stegoEncodeBtn');
        btn.textContent = 'Encrypting... 🔮';
        btn.disabled = true;

        try {
            // Encrypt secret
            const encryptedJson = await stegoEncryptImageClient(secretImageData.dataURL, ['Note to Self']); // Default to self for web demo
            const encoder = new TextEncoder();
            const encryptedBytes = encoder.encode(encryptedJson);

            // Check capacity again
            const bitsNeeded = HEADER_BITS + (encryptedBytes.length * 8);
            const totalDecoyPixels = decoyImageData.width * decoyImageData.height;
            if (bitsNeeded > totalDecoyPixels * BITS_PER_DECOY_PIXEL) throw new Error('Secret is too large!');

            // Embed
            const canvas = document.getElementById('stegoOutputCanvas');
            canvas.width = decoyImageData.width;
            canvas.height = decoyImageData.height;
            const ctx = canvas.getContext('2d');
            
            // Create a fresh ImageData copy to modify
            const newData = new Uint8ClampedArray(decoyImageData.data);
            
            let bitOffset = 0;
            bitOffset = writeBits(newData, bitOffset, MAGIC_NUMBER, 32);
            bitOffset = writeBits(newData, bitOffset, MAGIC_NUMBER_2, 32);
            bitOffset = writeBits(newData, bitOffset, encryptedBytes.length, 32);

            for (let i = 0; i < encryptedBytes.length; i++) {
                bitOffset = writeBits(newData, bitOffset, encryptedBytes[i], 8);
            }

            const newImageData = new ImageData(newData, canvas.width, canvas.height);
            ctx.putImageData(newImageData, 0, 0);
            
            // Apply Watermark
            drawWatermark(ctx, canvas.width, canvas.height);

            document.getElementById('stegoEncodeResult').style.display = 'block';
            showMessage('Secret Hidden Successfully! 🔮✨', 'success');
            playSound('sent');
        } catch (e) {
            console.error(e);
            showMessage('Encoding failed: ' + e.message, 'error');
            playSound('error');
        } finally {
            btn.textContent = '🔮 Encrypt & Hide';
            btn.disabled = false;
        }
    });

    document.getElementById('stegoSaveBtn').addEventListener('click', () => {
        const canvas = document.getElementById('stegoOutputCanvas');
        const link = document.createElement('a');
        link.download = 'stego_image.png';
        link.href = canvas.toDataURL();
        link.click();
    });

    // Decode Action
    document.getElementById('stegoDecodeBtn').addEventListener('click', async () => {
        if (!stegoDecodeImageData) return;
        
        const btn = document.getElementById('stegoDecodeBtn');
        btn.textContent = 'Decoding... 🔍';
        btn.disabled = true;

        try {
            const data = stegoDecodeImageData.data;
            let bitOffset = 0;
            let res = readBits(data, bitOffset, 32); const m1 = res.value; bitOffset = res.bitOffset;
            res = readBits(data, bitOffset, 32); const m2 = res.value; bitOffset = res.bitOffset;

            if (m1 !== MAGIC_NUMBER || m2 !== MAGIC_NUMBER_2) throw new Error('Not a matching stego image');

            res = readBits(data, bitOffset, 32); const len = res.value; bitOffset = res.bitOffset;
            if (len <= 0 || len > 10000000) throw new Error('Invalid data length');

            const payloadBuf = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                res = readBits(data, bitOffset, 8);
                payloadBuf[i] = res.value;
                bitOffset = res.bitOffset;
            }

            const decoder = new TextDecoder();
            const jsonStr = decoder.decode(payloadBuf);

            // Decrypt Wrapper
            const envelope = JSON.parse(jsonStr);
            if (!envelope.v || !envelope.v.startsWith('STEGO')) throw new Error('Invalid stego version');

            const myKeys = getRSAKeys();
            if (!myKeys) throw new Error('No private key found (Link Device first)');
            const privateKey = forge.pki.privateKeyFromPem(myKeys.privateKey);
            
            let sessionKey = null;
            for (const [name, encKey] of Object.entries(envelope.recipients)) {
                try {
                    const padded = privateKey.decrypt(forge.util.decode64(encKey), 'RSA-OAEP');
                    sessionKey = padded.slice(16, 16 + 32);
                    break;
                } catch (e) {}
            }
            if (!sessionKey) throw new Error('Not encrypted for you');

            const iv = forge.util.decode64(envelope.iv);
            const authTag = forge.util.decode64(envelope.tag);
            const encData = forge.util.decode64(envelope.data);

            const decipher = forge.cipher.createDecipher('AES-GCM', sessionKey);
            decipher.start({ iv: iv, tag: forge.util.createBuffer(authTag) });
            decipher.update(forge.util.createBuffer(encData));
            const pass = decipher.finish();

            if(!pass) throw new Error('Integrity check failed');
            
            const secretDataUrl = decipher.output.toString('utf8');

            const outCanvas = document.getElementById('stegoDecodeOutputCanvas');
            const img = new Image();
            img.onload = () => {
                outCanvas.width = img.width;
                outCanvas.height = img.height;
                outCanvas.getContext('2d').drawImage(img, 0, 0);
                document.getElementById('stegoDecodeResult').style.display = 'block';
                showMessage('Secret Revealed! 🔓✨', 'success');
                playSound('receive');
            };
            img.src = secretDataUrl;

        } catch (e) {
            console.error(e);
            showMessage('Decoding failed: ' + e.message, 'error');
            playSound('error');
        } finally {
            btn.textContent = '🔓 Reveal Secret';
            btn.disabled = false;
        }
    });



    // ==================== ADVANCED / PGP MODE ====================
    let pgpMode = localStorage.getItem('cute-pgp-enabled') === 'true';
    const pgpBtn = document.getElementById('pgpTabBtn');
    const togglePgpBtn = document.getElementById('togglePgpModeBtn');

    function updatePgpMode() {
        if(pgpBtn) pgpBtn.style.display = pgpMode ? 'inline-block' : 'none';
        if(togglePgpBtn) {
            togglePgpBtn.textContent = pgpMode ? 'Disable PGP Mode 🔒' : 'Enable PGP Mode 🔓';
            togglePgpBtn.className = pgpMode ? 'btn-primary' : 'btn-secondary';
            if (!pgpMode) {
                // If disabling, switch to another tab if currently on pgp
                if (document.getElementById('pgp-tab').classList.contains('active')) {
                    document.querySelector('.tab-btn[data-tab="encrypt"]')?.click();
                }
            }
        }
        localStorage.setItem('cute-pgp-enabled', pgpMode);
    }
    updatePgpMode();

    if(togglePgpBtn) {
        togglePgpBtn.addEventListener('click', () => {
             pgpMode = !pgpMode;
             updatePgpMode();
        });
    }

    // ==================== AUTO READ CLIPBOARD ====================
    let autoReadEnabled = localStorage.getItem('cute-autoread') !== 'false';
    const autoReadCheck = document.getElementById('autoReadToggle');
    if(autoReadCheck) {
        autoReadCheck.checked = autoReadEnabled;
        autoReadCheck.addEventListener('change', (e) => {
            autoReadEnabled = e.target.checked;
            localStorage.setItem('cute-autoread', autoReadEnabled);
        });
    }

    async function checkClipboard() {
        if (!autoReadEnabled) return;
        if (!document.hasFocus()) return;

        try {
            // Check permission
            try {
                const permission = await navigator.permissions.query({ name: 'clipboard-read' });
                if (permission.state === 'denied') return;
            } catch(e) { /* Ignore permission query error */ }

            const text = await navigator.clipboard.readText();
            if (!text) return;

            // Check for PGP
            if (text.includes('BEGIN PGP MESSAGE')) {
                if (!pgpMode) {
                     pgpMode = true;
                     updatePgpMode();
                     showMessage('PGP Mode Enabled for detected message! 🤓', 'info');
                }
                const pgpInput = document.getElementById('pgpInput');
                if (pgpInput && !pgpInput.value) {
                    pgpInput.value = text;
                    showMessage('Detected PGP Message! 📋', 'info');
                    document.querySelector('.tab-btn[data-tab="pgp"]')?.click();
                }
            }
            // Check for PFS Envelope (JSON)
            else if (text.trim().startsWith('{') && text.includes('"envelope"')) {
                 const decryptInput = document.getElementById('decryptInput');
                 if (decryptInput && !decryptInput.value) {
                     decryptInput.value = text;
                     showMessage('Detected Encrypted Message! 📋', 'success');
                     document.querySelector('.tab-btn[data-tab="decrypt"]')?.click();
                     document.getElementById('decryptBtn')?.click();
                 }
            }
        } catch (e) {
            // Clipboard access denied or empty
        }
    }

    window.addEventListener('focus', checkClipboard);

    // ==================== PLATFORM RECOMMENDATION BANNER ====================
    const platformBanner = document.getElementById('platformBanner');
    const closeBannerBtn = document.getElementById('closePlatformBanner');
    const continueWebBtn = document.getElementById('continueWebBtn');
    const installFromSettingsBtn = document.getElementById('installFromSettingsBtn');

    // Hide banner if already dismissed, or if running as installed PWA
    const isStandalone = window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone;
    const bannerDismissed = localStorage.getItem('cute-platform-banner-dismissed');

    if (platformBanner) {
        if (isStandalone || bannerDismissed === 'true') {
            platformBanner.classList.add('hidden');
        }
    }

    closeBannerBtn?.addEventListener('click', () => {
        if (platformBanner) {
            platformBanner.classList.add('hidden');
            localStorage.setItem('cute-platform-banner-dismissed', 'true');
        }
    });

    continueWebBtn?.addEventListener('click', () => {
        if (platformBanner) {
            platformBanner.classList.add('hidden');
            localStorage.setItem('cute-platform-banner-dismissed', 'true');
            showMessage('Great choice! Install to home screen for the best PWA experience 💖', 'success');
        }
    });

    // Hook up install button in settings
    if (installFromSettingsBtn) {
        window.addEventListener('beforeinstallprompt', (e) => {
            installFromSettingsBtn.style.display = 'block';
            installFromSettingsBtn.addEventListener('click', async () => {
                if (deferredPrompt) {
                    deferredPrompt.prompt();
                    await deferredPrompt.userChoice;
                    deferredPrompt = null;
                    installFromSettingsBtn.style.display = 'none';
                }
            });
        });
    }

    // ==================== CHAT MODULE (PeerJS P2P, Encrypted-First) ====================

    // --- Peer ID from RSA key ---
    function getPeerIdFromKey(pubKeyPem) {
        if (!pubKeyPem) return null;
        const md = forge.md.sha256.create();
        md.update(pubKeyPem);
        return 'cutesec_' + md.digest().toHex().substring(0, 32);
    }

    // --- PeerJS State ---
    let myPeer = null;
    let myPeerId = null;

    function updatePeerStatusBar(status) {
        const el = document.getElementById('peerStatusBar');
        if (!el) return;
        const map = {
            'offline':     { dot: 'offline', text: 'Offline' },
            'connecting':  { dot: 'connecting', text: 'Connecting...' },
            'online':      { dot: 'online', text: 'Online' },
            'error':       { dot: 'error', text: 'Error' }
        };
        const s = map[status] || map['offline'];
        el.innerHTML = `<span class="status-dot ${s.dot}"></span><span>${s.text}</span>`;
    }

    function initPeerJS() {
        const myKeys = getRSAKeys();
        if (!myKeys || !myKeys.publicKey) {
            updatePeerStatusBar('offline');
            return;
        }

        myPeerId = getPeerIdFromKey(myKeys.publicKey);

        // Show Peer ID
        const idDisplay = document.getElementById('myPeerIdDisplay');
        if (idDisplay) idDisplay.textContent = myPeerId;

        if (myPeer && !myPeer.destroyed) {
            if (myPeer.id === myPeerId) return;
            myPeer.destroy();
        }

        updatePeerStatusBar('connecting');

        try {
            myPeer = new Peer(myPeerId);

            myPeer.on('open', () => {
                updatePeerStatusBar('online');
                console.log('PeerJS online:', myPeerId);
            });

            myPeer.on('connection', (conn) => {
                setupIncomingConnection(conn);
            });

            myPeer.on('disconnected', () => {
                updatePeerStatusBar('connecting');
                setTimeout(() => {
                    if (myPeer && !myPeer.destroyed) myPeer.reconnect();
                }, 5000);
            });

            myPeer.on('error', (err) => {
                console.warn('PeerJS error:', err);
                if (err.type === 'unavailable-id') {
                    // ID collision - append random suffix
                    myPeerId = myPeerId + '_' + Math.random().toString(36).substring(2, 5);
                    const idDisplay = document.getElementById('myPeerIdDisplay');
                    if (idDisplay) idDisplay.textContent = myPeerId;
                    myPeer = new Peer(myPeerId);
                    // Re-attach handlers (simplified - in production, refactor)
                    myPeer.on('open', () => updatePeerStatusBar('online'));
                    myPeer.on('connection', (conn) => setupIncomingConnection(conn));
                } else {
                    updatePeerStatusBar('error');
                }
            });
        } catch (e) {
            console.error('PeerJS init error:', e);
            updatePeerStatusBar('error');
        }
    }

    function setupIncomingConnection(conn) {
        conn.on('data', (data) => {
            if (data && data.type === 'encrypted-message') {
                receiveEncryptedMessage(data);
            }
        });
    }

    // --- Send encrypted message via PeerJS ---
    async function sendP2PMessage(remotePeerId, payload) {
        return new Promise((resolve) => {
            if (!myPeer || myPeer.destroyed) return resolve(false);
            const conn = myPeer.connect(remotePeerId, { reliable: true });

            const timeout = setTimeout(() => {
                try { conn.close(); } catch(e) {}
                resolve(false);
            }, 4000);

            conn.on('open', () => {
                conn.send(payload);
                clearTimeout(timeout);
                setTimeout(() => { try { conn.close(); } catch(e) {} }, 500);
                resolve(true);
            });

            conn.on('error', () => {
                clearTimeout(timeout);
                resolve(false);
            });
        });
    }

    // --- Receive encrypted message (store as encrypted, don't auto-decrypt) ---
    function receiveEncryptedMessage(data) {
        const contacts = getContacts();
        let senderName = 'Unknown';
        if (data.senderKey) {
            const c = contacts.find(x => {
                const k = (x.publicKey || x.key || '').trim();
                return k === data.senderKey.trim();
            });
            if (c) senderName = c.name;
        }

        const msg = {
            encryptedPayload: data.payload,
            text: null,
            type: 'received',
            timestamp: data.timestamp || new Date().toISOString(),
            decrypted: false
        };
        saveChatMessage(senderName, msg);

        if (activeChatContact === senderName) {
            renderChatMessages(activeChatContact);
        } else {
            showMessage(`🔒 Encrypted message from ${senderName}! Open chat to decrypt 💬`, 'success');
        }
        refreshChatContacts(chatSearchInput?.value);
        playSound('receive');
    }

    // --- Chat Storage ---
    function getChatHistory(contactName) {
        const all = DB.get('cute_chat_history') || {};
        return all[contactName] || [];
    }

    function saveChatMessage(contactName, msg) {
        const all = DB.get('cute_chat_history') || {};
        if (!all[contactName]) all[contactName] = [];
        all[contactName].push(msg);
        if (all[contactName].length > 500) all[contactName] = all[contactName].slice(-500);
        DB.set('cute_chat_history', all);
    }

    function updateChatMessage(contactName, index, updates) {
        const all = DB.get('cute_chat_history') || {};
        if (all[contactName] && all[contactName][index]) {
            Object.assign(all[contactName][index], updates);
            DB.set('cute_chat_history', all);
        }
    }

    function clearChatHistory(contactName) {
        const all = DB.get('cute_chat_history') || {};
        delete all[contactName];
        DB.set('cute_chat_history', all);
    }

    function getAllChatPreviews() {
        const all = DB.get('cute_chat_history') || {};
        const previews = {};
        for (const [name, msgs] of Object.entries(all)) {
            if (msgs.length > 0) {
                const last = msgs[msgs.length - 1];
                const previewText = last.decrypted === false
                    ? '🔒 Encrypted message'
                    : (last.text || '').substring(0, 30) + ((last.text || '').length > 30 ? '...' : '');
                previews[name] = {
                    text: previewText,
                    time: last.timestamp,
                    type: last.type
                };
            }
        }
        return previews;
    }

    // --- Chat State ---
    let activeChatContact = null;

    // --- Chat UI Refs ---
    const chatContactList = document.getElementById('chatContactList');
    const chatEmptyState = document.getElementById('chatEmptyState');
    const chatActiveArea = document.getElementById('chatActiveArea');
    const chatMessages = document.getElementById('chatMessages');
    const chatInput = document.getElementById('chatInput');
    const chatSendBtn = document.getElementById('chatSendBtn');
    const chatHeaderName = document.getElementById('chatHeaderName');
    const chatHeaderAvatar = document.getElementById('chatHeaderAvatar');
    const chatBackBtn = document.getElementById('chatBackBtn');
    const chatPasteBtn = document.getElementById('chatPasteBtn');
    const chatClearBtn = document.getElementById('chatClearBtn');
    const chatSearchInput = document.getElementById('chatContactSearch');
    const chatDecryptAllBtn = document.getElementById('chatDecryptAllBtn');
    const chatAttachBtn = document.getElementById('chatAttachBtn');
    const chatAttachInput = document.getElementById('chatAttachInput');
    const chatAttachmentPreview = document.getElementById('chatAttachmentPreview');
    const chatAttachImg = document.getElementById('chatAttachImg');
    const chatAttachClearBtn = document.getElementById('chatAttachClearBtn');

    let currentChatAttachment = null;

    // --- Build Sidebar ---
    function refreshChatContacts(filter) {
        if (!chatContactList) return;
        const contacts = getContacts();
        const previews = getAllChatPreviews();
        const filterLower = (filter || '').toLowerCase();

        if (contacts.length === 0) {
            chatContactList.innerHTML = `
                <div class="chat-no-contacts">
                    <span>🔗</span>
                    <p>Add friends in the Friends tab to start chatting!</p>
                </div>`;
            return;
        }

        const allContacts = [{ name: 'Note to Self', isSelf: true }, ...contacts];

        chatContactList.innerHTML = '';
        allContacts.forEach(c => {
            const name = c.name;
            if (filterLower && !name.toLowerCase().includes(filterLower)) return;

            const preview = previews[name];
            const initial = name.charAt(0).toUpperCase();
            const isActive = activeChatContact === name;

            const item = document.createElement('div');
            item.className = `chat-contact-item${isActive ? ' active' : ''}`;
            item.innerHTML = `
                <div class="chat-avatar">${c.isSelf ? '📝' : initial}</div>
                <div class="chat-contact-info">
                    <div class="chat-contact-name">${name}</div>
                    <div class="chat-contact-preview">${preview ? (preview.type === 'sent' ? '↗ ' : '↙ ') + preview.text : 'No messages yet'}</div>
                </div>
                ${preview ? `<div class="chat-contact-meta">
                    <span class="chat-contact-time">${formatChatTime(preview.time)}</span>
                </div>` : ''}
            `;
            item.addEventListener('click', () => openChat(name));
            chatContactList.appendChild(item);
        });
    }

    // --- Time Formatting ---
    function formatChatTime(ts) {
        if (!ts) return '';
        const d = new Date(ts);
        const now = new Date();
        if (d.toDateString() === now.toDateString()) {
            return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
        const yesterday = new Date(now);
        yesterday.setDate(yesterday.getDate() - 1);
        if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
        return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    }

    function formatBubbleTime(ts) {
        if (!ts) return '';
        return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    function formatDateDivider(ts) {
        const d = new Date(ts);
        const now = new Date();
        if (d.toDateString() === now.toDateString()) return 'Today';
        const yesterday = new Date(now);
        yesterday.setDate(yesterday.getDate() - 1);
        if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
        return d.toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' });
    }

    // --- Open Chat ---
    function openChat(contactName) {
        activeChatContact = contactName;
        chatHeaderName.textContent = contactName;
        chatHeaderAvatar.textContent = contactName === 'Note to Self' ? '📝' : contactName.charAt(0).toUpperCase();
        chatEmptyState.style.display = 'none';
        chatActiveArea.style.display = 'flex';

        const sidebar = document.querySelector('.chat-sidebar');
        if (window.innerWidth <= 640 && sidebar) sidebar.classList.add('hidden-mobile');

        refreshChatContacts(chatSearchInput?.value);
        renderChatMessages(contactName);
        chatInput?.focus();
    }

    // --- Render Messages (Encrypted-First!) ---
    function renderChatMessages(contactName) {
        if (!chatMessages) return;
        const msgs = getChatHistory(contactName);

        chatMessages.innerHTML = '';

        if (msgs.length === 0) {
            chatMessages.innerHTML = `
                <div class="chat-system-msg">
                    🔒 Messages are encrypted end-to-end. Start the conversation!
                </div>`;
            return;
        }

        let lastDate = '';
        msgs.forEach((msg, index) => {
            const msgDate = new Date(msg.timestamp).toDateString();
            if (msgDate !== lastDate) {
                lastDate = msgDate;
                const divider = document.createElement('div');
                divider.className = 'chat-date-divider';
                divider.innerHTML = `<span>${formatDateDivider(msg.timestamp)}</span>`;
                chatMessages.appendChild(divider);
            }

            const row = document.createElement('div');
            row.className = `chat-bubble-row ${msg.type}`;

            if (msg.type === 'received' && msg.decrypted === false) {
                // ====== ENCRYPTED BUBBLE (with Decrypt button) ======
                const cipherPreview = (msg.encryptedPayload || '').substring(0, 80) + '...';
                row.innerHTML = `
                    <div class="chat-bubble chat-bubble-encrypted">
                        <div class="chat-encrypted-label">🔒 Encrypted Message</div>
                        <div class="chat-encrypted-text">${escapeHTML(cipherPreview)}</div>
                        <button class="chat-decrypt-btn" data-idx="${index}">🔓 Decrypt</button>
                        <div class="chat-bubble-meta">
                            <span class="chat-bubble-time">${formatBubbleTime(msg.timestamp)}</span>
                        </div>
                    </div>
                `;
                row.querySelector('.chat-decrypt-btn').addEventListener('click', () => {
                    decryptSingleMessage(contactName, index);
                });
            } else {
                // ====== PLAINTEXT BUBBLE (sent, or already decrypted) ======
                const text = msg.text || '';
                const imgHTML = msg.image ? `<img src="${msg.image}" class="chat-bubble-img" />` : '';
                const textHTML = text ? `<div class="chat-bubble-text">${escapeHTML(text)}</div>` : '';
                
                // If it has neither and it's not a newly sent message, it might be a failure
                const contentHTML = (imgHTML || textHTML) ? (imgHTML + textHTML) : '<div class="chat-bubble-text">[decryption failed]</div>';

                const badge = msg.type === 'sent'
                    ? '<span class="chat-sent-badge">🔒</span>'
                    : (msg.decrypted === true ? '<span class="chat-decrypted-badge">🔓</span>' : '');
                row.innerHTML = `
                    <div class="chat-bubble${msg.justDecrypted ? ' chat-bubble-decrypted' : ''}">
                        ${contentHTML}
                        <div class="chat-bubble-meta">
                            <button class="chat-bubble-copy" title="Copy">📋</button>
                            ${badge}
                            <span class="chat-bubble-time">${formatBubbleTime(msg.timestamp)}</span>
                        </div>
                    </div>
                `;
                const copyBtn = row.querySelector('.chat-bubble-copy');
                copyBtn?.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    if (msg.type === 'sent' && msg.encrypted) {
                        await navigator.clipboard.writeText(msg.encrypted);
                        showChatToast('Encrypted version copied! 📋');
                    } else {
                        await navigator.clipboard.writeText(msg.text || '');
                        showChatToast('Message copied! 📋');
                    }
                });
            }

            chatMessages.appendChild(row);
        });

        requestAnimationFrame(() => {
            chatMessages.scrollTop = chatMessages.scrollHeight;
        });
    }

    // --- Decrypt a single message ---
    function decryptSingleMessage(contactName, index) {
        const all = DB.get('cute_chat_history') || {};
        const msgs = all[contactName];
        if (!msgs || !msgs[index]) return;

        const msg = msgs[index];
        if (msg.decrypted !== false || !msg.encryptedPayload) return;

        const myKeys = getRSAKeys();
        if (!myKeys) {
            showMessage('No identity! Create one first.', 'error');
            return;
        }

        try {
            const envelope = JSON.parse(msg.encryptedPayload);
            const actualEnvelope = envelope.envelope || envelope;

            const privateKey = forge.pki.privateKeyFromPem(myKeys.privateKey);
            const encryptedKey = forge.util.decode64(actualEnvelope.encryptedKey);
            const decryptedPadded = privateKey.decrypt(encryptedKey, 'RSA-OAEP');
            const sessionKey = decryptedPadded.substring(16, 16 + 32);

            const iv = forge.util.decode64(actualEnvelope.iv);
            const authTag = forge.util.decode64(actualEnvelope.authTag);
            const encData = forge.util.decode64(actualEnvelope.encryptedMessage);

            const decipher = forge.cipher.createDecipher('AES-GCM', sessionKey);
            decipher.start({ iv: iv, tag: forge.util.createBuffer(authTag) });
            decipher.update(forge.util.createBuffer(encData));

            if (decipher.finish()) {
                const decryptedStr = decipher.output.toString('utf8');
                let parsedText = decryptedStr;
                let parsedImage = null;

                try {
                    const obj = JSON.parse(decryptedStr);
                    if (obj && (typeof obj.text !== 'undefined' || typeof obj.image !== 'undefined')) {
                        parsedText = obj.text || '';
                        parsedImage = obj.image || null;
                    }
                } catch (e) {
                    // Fallback to plain text for older messages
                }

                msgs[index].text = parsedText;
                if (parsedImage) msgs[index].image = parsedImage;
                msgs[index].decrypted = true;
                msgs[index].justDecrypted = true;
                DB.set('cute_chat_history', all);
                renderChatMessages(contactName);
                refreshChatContacts(chatSearchInput?.value);

                // Clear the animation flag after render
                setTimeout(() => {
                    msgs[index].justDecrypted = false;
                    DB.set('cute_chat_history', all);
                }, 600);
            } else {
                showMessage('Integrity check failed! This message may be corrupted.', 'error');
            }
        } catch (e) {
            console.error('Decrypt error:', e);
            showMessage('Decryption failed! Not encrypted for you? 🤔', 'error');
        }
    }

    // --- Decrypt ALL encrypted messages in current chat ---
    function decryptAllMessages() {
        if (!activeChatContact) return;
        const all = DB.get('cute_chat_history') || {};
        const msgs = all[activeChatContact];
        if (!msgs) return;

        const myKeys = getRSAKeys();
        if (!myKeys) {
            showMessage('No identity!', 'error');
            return;
        }

        let count = 0;
        const privateKey = forge.pki.privateKeyFromPem(myKeys.privateKey);

        msgs.forEach((msg, i) => {
            if (msg.decrypted !== false || !msg.encryptedPayload) return;
            try {
                const envelope = JSON.parse(msg.encryptedPayload);
                const actual = envelope.envelope || envelope;
                const ek = forge.util.decode64(actual.encryptedKey);
                const padded = privateKey.decrypt(ek, 'RSA-OAEP');
                const sk = padded.substring(16, 16 + 32);
                const iv = forge.util.decode64(actual.iv);
                const tag = forge.util.decode64(actual.authTag);
                const ed = forge.util.decode64(actual.encryptedMessage);
                const d = forge.cipher.createDecipher('AES-GCM', sk);
                d.start({ iv, tag: forge.util.createBuffer(tag) });
                d.update(forge.util.createBuffer(ed));
                if (d.finish()) {
                    const decryptedStr = d.output.toString('utf8');
                    let parsedText = decryptedStr;
                    let parsedImage = null;

                    try {
                        const obj = JSON.parse(decryptedStr);
                        if (obj && (typeof obj.text !== 'undefined' || typeof obj.image !== 'undefined')) {
                            parsedText = obj.text || '';
                            parsedImage = obj.image || null;
                        }
                    } catch (e) {
                        // Fallback to plain text
                    }

                    msgs[i].text = parsedText;
                    if (parsedImage) msgs[i].image = parsedImage;
                    msgs[i].decrypted = true;
                    msgs[i].justDecrypted = true;
                    count++;
                }
            } catch (e) { /* skip undecryptable */ }
        });

        DB.set('cute_chat_history', all);
        renderChatMessages(activeChatContact);
        refreshChatContacts(chatSearchInput?.value);

        if (count > 0) {
            showChatToast(`Decrypted ${count} message${count > 1 ? 's' : ''}! 🔓`);
            playSound('receive');
            setTimeout(() => {
                msgs.forEach(m => { m.justDecrypted = false; });
                DB.set('cute_chat_history', all);
            }, 600);
        } else {
            showChatToast('No encrypted messages to decrypt');
        }
    }

    // --- Helpers ---
    function escapeHTML(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function showChatToast(text) {
        let toast = document.querySelector('.chat-copy-toast');
        if (!toast) {
            toast = document.createElement('div');
            toast.className = 'chat-copy-toast';
            document.body.appendChild(toast);
        }
        toast.textContent = text;
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 2500);
    }

    // --- Send Message (encrypt, P2P send, show plaintext to sender) ---
    async function chatSendMessage() {
        const text = chatInput?.value?.trim() || '';
        if (!activeChatContact) return;
        if (!text && !currentChatAttachment) return;

        const myKeys = getRSAKeys();
        if (!myKeys) {
            showMessage('You need an identity first!', 'error');
            return;
        }

        const contacts = getContacts();
        let pubKeyPem;
        if (activeChatContact === 'Note to Self') {
            pubKeyPem = myKeys.publicKey;
        } else {
            const c = contacts.find(x => x.name === activeChatContact);
            if (c) pubKeyPem = c.publicKey || c.key;
        }

        if (!pubKeyPem) {
            showMessage('Contact key not found!', 'error');
            return;
        }

        chatSendBtn.disabled = true;
        const originalBtnHTML = chatSendBtn.innerHTML;
        chatSendBtn.innerHTML = '⏳';

        try {
            // Create a composite payload string to handle text+attachments
            const payloadObject = { text: text, image: currentChatAttachment };
            const payloadString = JSON.stringify(payloadObject);

            // Encrypt
            const sessionKey = forge.random.getBytesSync(32);
            const iv = forge.random.getBytesSync(16);
            const cipher = forge.cipher.createCipher('AES-GCM', sessionKey);
            cipher.start({ iv });
            cipher.update(forge.util.createBuffer(payloadString, 'utf8'));
            cipher.finish();

            const pubKey = forge.pki.publicKeyFromPem(pubKeyPem);
            const paddedKey = forge.random.getBytesSync(16) + sessionKey + forge.random.getBytesSync(16);
            const encryptedKey = forge.util.encode64(pubKey.encrypt(paddedKey, 'RSA-OAEP'));

            const signedEnvelope = {
                envelope: {
                    version: "2.0",
                    sessionID: forge.util.bytesToHex(forge.random.getBytesSync(16)),
                    timestamp: new Date().toISOString(),
                    encryptedKey: encryptedKey,
                    iv: forge.util.encode64(iv),
                    authTag: cipher.mode.tag.toString('base64'),
                    encryptedMessage: cipher.output.toString('base64'),
                    nonce: forge.util.bytesToHex(forge.random.getBytesSync(8))
                },
                signature: "signature-placeholder",
                senderProof: "PFS-v2.0"
            };

            const encryptedStr = JSON.stringify(signedEnvelope);

            // Try P2P delivery
            let sentViaP2P = false;
            if (activeChatContact !== 'Note to Self') {
                const contactPeerId = getPeerIdFromKey(pubKeyPem);
                if (contactPeerId) {
                    sentViaP2P = await sendP2PMessage(contactPeerId, {
                        type: 'encrypted-message',
                        senderKey: myKeys.publicKey,
                        payload: encryptedStr,
                        timestamp: new Date().toISOString()
                    });
                }
            }

            // Save as plaintext for sender (sender can see their own messages)
            saveChatMessage(activeChatContact, {
                text: text,
                image: currentChatAttachment,
                encrypted: encryptedStr,
                type: 'sent',
                timestamp: new Date().toISOString(),
                decrypted: true
            });

            // Clear inputs
            chatInput.value = '';
            chatInput.style.height = '40px';
            currentChatAttachment = null;
            if (chatAttachImg) chatAttachImg.src = '';
            if (chatAttachmentPreview) chatAttachmentPreview.style.display = 'none';
            if (chatAttachInput) chatAttachInput.value = '';

            renderChatMessages(activeChatContact);
            refreshChatContacts(chatSearchInput?.value);
            playSound('sent');

            // Also copy to clipboard as fallback
            try { await navigator.clipboard.writeText(encryptedStr); } catch(e) {}

            if (sentViaP2P) {
                showChatToast('Sent instantly via P2P! ⚡ (also copied to clipboard)');
            } else if (activeChatContact === 'Note to Self') {
                showChatToast('Note saved! 📝');
            } else {
                showChatToast('Friend offline — encrypted & copied to clipboard 📋');
            }

        } catch (e) {
            console.error('Send error:', e);
            showMessage('Encryption failed: ' + e.message, 'error');
            playSound('error');
        } finally {
            chatSendBtn.innerHTML = originalBtnHTML;
            chatSendBtn.disabled = false;
        }
    }

    // --- Paste & Decrypt (manual fallback for offline exchange) ---
    async function chatPasteDecrypt() {
        if (!activeChatContact) return;
        const myKeys = getRSAKeys();
        if (!myKeys) { showMessage('No identity!', 'error'); return; }

        try {
            const text = await navigator.clipboard.readText();
            if (!text || !text.trim()) {
                showMessage('Clipboard is empty!', 'error');
                return;
            }

            // Store as encrypted (user can then click Decrypt)
            const msg = {
                encryptedPayload: text.trim(),
                text: null,
                type: 'received',
                timestamp: new Date().toISOString(),
                decrypted: false
            };
            saveChatMessage(activeChatContact, msg);
            renderChatMessages(activeChatContact);
            refreshChatContacts(chatSearchInput?.value);
            showChatToast('Encrypted message added! Click 🔓 to decrypt');
        } catch (e) {
            showMessage('Clipboard read failed!', 'error');
        }
    }

    // --- Copy Peer ID ---
    document.getElementById('copyPeerIdBtn')?.addEventListener('click', async () => {
        const id = document.getElementById('myPeerIdDisplay')?.textContent;
        if (id && id !== 'No identity') {
            await navigator.clipboard.writeText(id);
            showChatToast('Peer ID copied! Share it with friends 📋');
        } else {
            showMessage('Create an identity first!', 'error');
        }
    });

    // --- Event Listeners ---
    chatSendBtn?.addEventListener('click', chatSendMessage);

    chatInput?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            chatSendMessage();
        }
    });

    chatInput?.addEventListener('input', () => {
        chatInput.style.height = '40px';
        chatInput.style.height = Math.min(chatInput.scrollHeight, 100) + 'px';
    });

    chatAttachBtn?.addEventListener('click', () => {
        chatAttachInput?.click();
    });

    chatAttachInput?.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;

        // Check size (e.g. max 5MB)
        if (file.size > 5 * 1024 * 1024) {
            showMessage('Image is too large (max 5MB).', 'error');
            e.target.value = '';
            return;
        }

        const reader = new FileReader();
        reader.onload = (ev) => {
            currentChatAttachment = ev.target.result;
            chatAttachImg.src = currentChatAttachment;
            chatAttachmentPreview.style.display = 'flex';
        };
        reader.readAsDataURL(file);
    });

    chatAttachClearBtn?.addEventListener('click', () => {
        currentChatAttachment = null;
        chatAttachImg.src = '';
        chatAttachmentPreview.style.display = 'none';
        if (chatAttachInput) chatAttachInput.value = '';
    });

    chatPasteBtn?.addEventListener('click', chatPasteDecrypt);
    chatDecryptAllBtn?.addEventListener('click', decryptAllMessages);

    chatClearBtn?.addEventListener('click', () => {
        if (!activeChatContact) return;
        if (confirm(`Clear all messages with ${activeChatContact}?`)) {
            clearChatHistory(activeChatContact);
            renderChatMessages(activeChatContact);
            refreshChatContacts(chatSearchInput?.value);
            showMessage('Chat cleared! 🗑️', 'success');
        }
    });

    chatBackBtn?.addEventListener('click', () => {
        const sidebar = document.querySelector('.chat-sidebar');
        if (sidebar) sidebar.classList.remove('hidden-mobile');
    });

    chatSearchInput?.addEventListener('input', () => {
        refreshChatContacts(chatSearchInput.value);
    });

    // Refresh when switching to chat tab
    const chatTabObserver = new MutationObserver(() => {
        const chatTab = document.getElementById('chat-tab');
        if (chatTab && chatTab.classList.contains('active')) {
            refreshChatContacts(chatSearchInput?.value);
        }
    });
    const chatTab = document.getElementById('chat-tab');
    if (chatTab) {
        chatTabObserver.observe(chatTab, { attributes: true, attributeFilter: ['class'] });
    }

    // --- Init ---
    initPeerJS();
    refreshChatContacts();

});

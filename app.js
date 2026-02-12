// ==================== CUTE SECURE MESSENGER PWA ====================
// All crypto runs client-side — nothing leaves your device

document.addEventListener('DOMContentLoaded', async () => {

    // ==================== STORAGE ====================
    const DB = {
        get(key) { try { return JSON.parse(localStorage.getItem(key)); } catch { return null; } },
        set(key, val) { localStorage.setItem(key, JSON.stringify(val)); },
        remove(key) { localStorage.removeItem(key); }
    };

    // ==================== SERVICE WORKER ====================
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('./sw.js').catch(e => console.warn('SW failed:', e));
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

    // ==================== TAB SWITCHING ====================
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.getAttribute('data-tab');
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            tabPanes.forEach(p => {
                p.classList.remove('active');
                if (p.id === `${tabId}-tab`) p.classList.add('active');
            });
        });
    });

    // ==================== MESSAGE HELPER ====================
    function showMessage(text, type) {
        const el = document.getElementById('message');
        el.textContent = text;
        el.className = `message ${type}`;
        el.style.display = 'block';
        setTimeout(() => { el.style.display = 'none'; }, 3500);
    }

    // ==================== KEY MANAGEMENT ====================
    // This PWA uses PGP as the primary encryption method (works everywhere)
    
    function getMyKeys() { return DB.get('cute_pgp_keys') || []; }
    function saveMyKeys(keys) { DB.set('cute_pgp_keys', keys); }
    function getContacts() { return DB.get('cute_contacts') || []; }
    function saveContacts(contacts) { DB.set('cute_contacts', contacts); }

    // Load primary key into UI
    function loadMyPublicKey() {
        const keys = getMyKeys();
        const keyArea = document.getElementById('myPublicKey');
        if (keys.length > 0 && keyArea) {
            keyArea.value = keys[0].publicKey;
            document.getElementById('keyStatus').textContent = '✨ Ready to send secure messages!';
            document.getElementById('keyStatus').style.color = '#228B22';
        } else {
            if (keyArea) keyArea.value = '';
            document.getElementById('keyStatus').textContent = '🔑 Generate a PGP key in the PGP tab to get started!';
            document.getElementById('keyStatus').style.color = '#FF8C00';
        }
    }

    // ==================== CONTACTS ====================

    function loadContactsUI() {
        const contacts = getContacts();
        
        // Recipient select
        const select = document.getElementById('recipientSelect');
        const currentVals = Array.from(select.selectedOptions).map(o => o.value);
        select.innerHTML = '';
        contacts.forEach(c => {
            const opt = document.createElement('option');
            opt.value = c.name;
            opt.textContent = c.name;
            if (currentVals.includes(c.name)) opt.selected = true;
            select.appendChild(opt);
        });

        // Contact cards
        const container = document.getElementById('contactsContainer');
        if (contacts.length > 0) {
            container.innerHTML = contacts.map(c => `
                <div class="contact-card">
                    <div class="contact-avatar">${c.name.charAt(0).toUpperCase()}</div>
                    <div class="contact-name">${c.name}</div>
                    <div class="contact-actions">
                        <button class="btn-danger btn-small remove-contact-btn" data-name="${c.name}">🗑️</button>
                    </div>
                </div>
            `).join('');
            container.querySelectorAll('.remove-contact-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const name = btn.getAttribute('data-name');
                    if (confirm(`Remove ${name}?`)) {
                        const updated = getContacts().filter(c => c.name !== name);
                        saveContacts(updated);
                        loadContactsUI();
                        showMessage(`${name} removed 👋`, 'success');
                    }
                });
            });
        } else {
            container.innerHTML = '<p class="no-contacts">No friends added yet! Add your first friend above 💕</p>';
        }
    }

    // Add contact
    document.getElementById('addContactFormBtn').addEventListener('click', async () => {
        const name = document.getElementById('newContactName').value.trim();
        const keyText = document.getElementById('newContactKey').value.trim();
        if (!name) return showMessage('Enter a name! 💕', 'error');
        if (!keyText) return showMessage('Paste their PGP public key! 🔑', 'error');
        try {
            // Validate it's a real PGP key
            await openpgp.readKey({ armoredKey: keyText });
            const contacts = getContacts();
            if (contacts.find(c => c.name === name)) return showMessage('Friend already exists!', 'error');
            contacts.push({ name, publicKey: keyText });
            saveContacts(contacts);
            document.getElementById('newContactName').value = '';
            document.getElementById('newContactKey').value = '';
            loadContactsUI();
            showMessage(`Added ${name}! 🎉`, 'success');
        } catch (e) {
            showMessage('Invalid PGP key format! 😢', 'error');
        }
    });

    // Copy my key
    document.getElementById('copyKeyBtn').addEventListener('click', async () => {
        const key = document.getElementById('myPublicKey').value;
        if (key) {
            await navigator.clipboard.writeText(key);
            showMessage('Public key copied! 📋', 'success');
        }
    });

    // ==================== ENCRYPT (PGP-BASED) ====================

    document.getElementById('encryptBtn').addEventListener('click', async () => {
        const text = document.getElementById('encryptInput').value.trim();
        const select = document.getElementById('recipientSelect');
        const recipientNames = Array.from(select.selectedOptions).map(o => o.value);
        if (!text) return showMessage('Type a message! 💬', 'error');
        if (recipientNames.length === 0) return showMessage('Select at least one friend! 👩‍❤️‍👨', 'error');
        try {
            const contacts = getContacts();
            const myKeys = getMyKeys();
            const results = {};

            for (const name of recipientNames) {
                const contact = contacts.find(c => c.name === name);
                if (!contact) continue;
                const recipientKey = await openpgp.readKey({ armoredKey: contact.publicKey });
                const encKeys = [recipientKey];
                // Also encrypt for self so sender can read their own message
                if (myKeys.length > 0) {
                    encKeys.push(await openpgp.readKey({ armoredKey: myKeys[0].publicKey }));
                }
                const message = await openpgp.createMessage({ text });
                const encrypted = await openpgp.encrypt({ message, encryptionKeys: encKeys });
                results[name] = encrypted;
            }

            displayEncryptResults(results);
            showMessage(`Encrypted for ${recipientNames.length} friend(s)! ✨`, 'success');
        } catch (e) {
            showMessage(`Encryption failed: ${e.message}`, 'error');
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

    // Copy All
    document.getElementById('copyAllBtn').addEventListener('click', async () => {
        const items = document.querySelectorAll('#multiEncryptResults .result-text');
        if (items.length === 0) return showMessage('No messages to copy!', 'error');
        let combined = '';
        items.forEach(t => { combined += t.value + '\n\n'; });
        await navigator.clipboard.writeText(combined);
        showMessage('All messages copied! 📋', 'success');
    });

    // ==================== DECRYPT ====================

    document.getElementById('decryptBtn').addEventListener('click', async () => {
        const text = document.getElementById('decryptInput').value.trim();
        if (!text) return showMessage('Paste an encrypted message! 🔐', 'error');
        try {
            const myKeys = getMyKeys();
            if (myKeys.length === 0) return showMessage('Generate a PGP key first!', 'error');
            const privateKey = await openpgp.readPrivateKey({ armoredKey: myKeys[0].privateKey });
            let decKey = privateKey;
            if (myKeys[0].hasPassphrase) {
                const pass = prompt('Enter your PGP passphrase:');
                if (pass) decKey = await openpgp.decryptKey({ privateKey, passphrase: pass });
            }
            const message = await openpgp.readMessage({ armoredMessage: text });
            const { data } = await openpgp.decrypt({ message, decryptionKeys: decKey });
            document.getElementById('decryptOutput').value = data;
            showMessage('Decrypted! 💖', 'success');
        } catch (e) {
            showMessage(`Decryption failed: ${e.message}`, 'error');
        }
    });

    document.getElementById('copyDecryptBtn').addEventListener('click', async () => {
        const text = document.getElementById('decryptOutput').value;
        if (text) { await navigator.clipboard.writeText(text); showMessage('Copied! 📋', 'success'); }
    });

    // ==================== STEGANOGRAPHY ====================

    let decoyImageData = null, secretImageData = null, stegoDecodeImageData = null;
    const BITS_PER_CHANNEL = 2;
    const CHANNELS_USED = 3;
    const BITS_PER_PIXEL = BITS_PER_CHANNEL * CHANNELS_USED;
    const HEADER_BITS = 96;
    const MAGIC1 = 0xC5E0C5E0;
    const MAGIC2 = 0x57E60827;

    // Stego mode toggle
    document.querySelectorAll('.stego-mode-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.stego-mode-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.stego-section').forEach(s => s.classList.remove('active'));
            document.getElementById(`stego-${btn.getAttribute('data-stego-mode')}`).classList.add('active');
        });
    });

    function loadImageFromFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const img = new Image();
                img.onload = () => {
                    const c = document.createElement('canvas');
                    c.width = img.width; c.height = img.height;
                    const ctx = c.getContext('2d');
                    ctx.drawImage(img, 0, 0);
                    resolve({ width: img.width, height: img.height, data: ctx.getImageData(0, 0, img.width, img.height).data, dataURL: e.target.result });
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
        if (!zone || !input) return;
        zone.addEventListener('click', () => input.click());
        zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('drag-over'); });
        zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
        zone.addEventListener('drop', (e) => {
            e.preventDefault(); zone.classList.remove('drag-over');
            if (e.dataTransfer.files[0]?.type.startsWith('image/')) handleFile(e.dataTransfer.files[0]);
        });
        input.addEventListener('change', (e) => { if (e.target.files[0]) handleFile(e.target.files[0]); });
        async function handleFile(file) {
            try {
                const data = await loadImageFromFile(file);
                document.getElementById(placeholderId).style.display = 'none';
                const prev = document.getElementById(previewId);
                prev.src = data.dataURL; prev.style.display = 'block';
                if (infoId) document.getElementById(infoId).textContent = `${data.width}×${data.height} · ${(file.size/1024).toFixed(1)}KB`;
                onLoad(data);
            } catch { showMessage('Failed to load image!', 'error'); }
        }
    }

    setupUploadZone('decoyDropZone', 'decoyImageInput', 'decoyPlaceholder', 'decoyPreview', 'decoyInfo', d => { decoyImageData = d; updateCapacity(); updateEncodeBtn(); });
    setupUploadZone('secretDropZone', 'secretImageInput', 'secretPlaceholder', 'secretPreview', 'secretInfo', d => { secretImageData = d; updateCapacity(); updateEncodeBtn(); });
    setupUploadZone('stegoDecodeDropZone', 'stegoDecodeInput', 'stegoDecodePlaceholder', 'stegoDecodePreview', null, d => { stegoDecodeImageData = d; document.getElementById('stegoDecodeBtn').disabled = false; });

    function updateEncodeBtn() { document.getElementById('stegoEncodeBtn').disabled = !(decoyImageData && secretImageData); }
    function updateCapacity() {
        const bar = document.getElementById('stegoCapacityBar');
        const txt = document.getElementById('stegoCapacityText');
        if (!decoyImageData) { bar.style.width = '0%'; txt.textContent = 'Select both images'; return; }
        const cap = (decoyImageData.width * decoyImageData.height * BITS_PER_PIXEL - HEADER_BITS) / 8;
        const need = secretImageData ? Math.ceil(secretImageData.dataURL.length * 1.4) + 800 : 0;
        const pct = need > 0 ? Math.min((need / cap) * 100, 100) : 0;
        bar.style.width = pct + '%';
        bar.style.background = pct > 90 ? '#e74c3c' : pct > 60 ? '#f39c12' : '#2ecc71';
        txt.textContent = need > 0 ? `${(need/1024).toFixed(1)}KB / ${(cap/1024).toFixed(1)}KB (${pct.toFixed(0)}%)` : `Capacity: ${(cap/1024).toFixed(1)}KB`;
    }

    function writeBits(data, offset, value, numBits) {
        for (let i = numBits - 1; i >= 0; i--) {
            const bit = (value >> i) & 1;
            const px = Math.floor(offset / BITS_PER_PIXEL);
            const ch = Math.floor((offset % BITS_PER_PIXEL) / BITS_PER_CHANNEL);
            const bi = offset % BITS_PER_CHANNEL;
            const idx = px * 4 + ch;
            const mask = ~(1 << (BITS_PER_CHANNEL - 1 - bi));
            data[idx] = (data[idx] & mask) | (bit << (BITS_PER_CHANNEL - 1 - bi));
            offset++;
        }
        return offset;
    }

    function readBits(data, offset, numBits) {
        let val = 0;
        for (let i = numBits - 1; i >= 0; i--) {
            const px = Math.floor(offset / BITS_PER_PIXEL);
            const ch = Math.floor((offset % BITS_PER_PIXEL) / BITS_PER_CHANNEL);
            const bi = offset % BITS_PER_CHANNEL;
            const idx = px * 4 + ch;
            val |= (((data[idx] >> (BITS_PER_CHANNEL - 1 - bi)) & 1) << i);
            offset++;
        }
        return { value: val, offset };
    }

    // Stego Encode
    document.getElementById('stegoEncodeBtn').addEventListener('click', async () => {
        if (!decoyImageData || !secretImageData) return;
        try {
            const payload = new TextEncoder().encode(secretImageData.dataURL);
            const capBits = decoyImageData.width * decoyImageData.height * BITS_PER_PIXEL - HEADER_BITS;
            if (payload.length * 8 > capBits) return showMessage('Secret too large for this decoy!', 'error');

            const canvas = document.createElement('canvas');
            canvas.width = decoyImageData.width; canvas.height = decoyImageData.height;
            const ctx = canvas.getContext('2d');
            const imgData = ctx.createImageData(canvas.width, canvas.height);
            imgData.data.set(new Uint8Array(decoyImageData.data));

            let off = 0;
            off = writeBits(imgData.data, off, MAGIC1, 32);
            off = writeBits(imgData.data, off, MAGIC2, 32);
            off = writeBits(imgData.data, off, payload.length, 32);
            for (let i = 0; i < payload.length; i++) off = writeBits(imgData.data, off, payload[i], 8);

            ctx.putImageData(imgData, 0, 0);
            const outCanvas = document.getElementById('stegoOutputCanvas');
            outCanvas.width = canvas.width; outCanvas.height = canvas.height;
            outCanvas.getContext('2d').drawImage(canvas, 0, 0);
            document.getElementById('stegoEncodeResult').style.display = 'block';
            showMessage('Hidden successfully! 🤫', 'success');
        } catch (e) { showMessage('Encoding failed: ' + e.message, 'error'); }
    });

    // Stego Save
    document.getElementById('stegoSaveBtn')?.addEventListener('click', () => {
        const canvas = document.getElementById('stegoOutputCanvas');
        const a = document.createElement('a');
        a.download = `stego_${Date.now()}.png`;
        a.href = canvas.toDataURL('image/png');
        a.click();
    });

    // Stego Decode
    document.getElementById('stegoDecodeBtn').addEventListener('click', () => {
        if (!stegoDecodeImageData) return;
        try {
            const d = stegoDecodeImageData.data;
            let off = 0;
            let r = readBits(d, off, 32); off = r.offset; const m1 = r.value;
            r = readBits(d, off, 32); off = r.offset; const m2 = r.value;
            if (m1 !== MAGIC1 || m2 !== MAGIC2) return showMessage('No hidden data found!', 'error');
            r = readBits(d, off, 32); off = r.offset; const len = r.value;
            if (len <= 0 || len > 50000000) return showMessage('Invalid hidden data!', 'error');

            const buf = new Uint8Array(len);
            for (let i = 0; i < len; i++) { r = readBits(d, off, 8); buf[i] = r.value; off = r.offset; }

            const dataUrl = new TextDecoder().decode(buf);
            if (dataUrl.startsWith('data:image')) {
                const img = new Image();
                img.onload = () => {
                    const c = document.getElementById('stegoDecodeOutputCanvas');
                    c.width = img.width; c.height = img.height;
                    c.getContext('2d').drawImage(img, 0, 0);
                    document.getElementById('stegoDecodeResult').style.display = 'block';
                    showMessage('Secret revealed! 🤫', 'success');
                };
                img.src = dataUrl;
            } else {
                showMessage('Hidden data is not an image (might be encrypted for a specific recipient)', 'error');
            }
        } catch (e) { showMessage('Decode failed: ' + e.message, 'error'); }
    });

    // ==================== PGP ====================

    const pgpGenModal = document.getElementById('pgpGenModal');
    document.getElementById('pgpNewKeyBtn').addEventListener('click', () => { pgpGenModal.style.display = 'block'; });
    document.getElementById('closePgpGen').addEventListener('click', () => { pgpGenModal.style.display = 'none'; });
    window.addEventListener('click', (e) => { if (e.target === pgpGenModal) pgpGenModal.style.display = 'none'; });

    // Generate PGP Key
    document.getElementById('pgpGenerateActionBtn').addEventListener('click', async () => {
        const name = document.getElementById('pgpGenName').value.trim();
        const email = document.getElementById('pgpGenEmail').value.trim();
        const pass = document.getElementById('pgpGenPass').value;
        if (!name || !email) return showMessage('Name and email required!', 'error');
        const btn = document.getElementById('pgpGenerateActionBtn');
        try {
            btn.disabled = true; btn.textContent = '⏳ Generating (this may take a moment)...';
            const { privateKey, publicKey } = await openpgp.generateKey({
                type: 'ecc', curve: 'curve25519',
                userIDs: [{ name, email }],
                passphrase: pass || undefined
            });
            const keys = getMyKeys();
            keys.push({ id: Date.now().toString(), name, email, publicKey, privateKey, hasPassphrase: !!pass, createdAt: new Date().toISOString() });
            saveMyKeys(keys);
            pgpGenModal.style.display = 'none';
            refreshPGPKeyList();
            loadMyPublicKey();
            loadContactsUI();
            showMessage('PGP Key generated! 🔑', 'success');
        } catch (e) { showMessage('Key gen failed: ' + e.message, 'error'); }
        finally { btn.disabled = false; btn.textContent = 'Generate Key 🔑'; }
    });

    function refreshPGPKeyList() {
        const list = document.getElementById('pgpKeyList');
        const sel = document.getElementById('pgpRecipientSelect');
        const myKeys = getMyKeys();
        const contacts = getContacts();
        list.innerHTML = ''; sel.innerHTML = '';

        if (myKeys.length === 0 && contacts.length === 0) {
            list.innerHTML = '<p style="color:#aaa;text-align:center;padding:20px;">No keys yet.<br>Generate one!</p>';
            return;
        }

        myKeys.forEach(k => {
            const d = document.createElement('div'); d.className = 'pgp-key-item';
            d.innerHTML = `<strong>🔐 ${k.name}</strong><br><small>${k.email}</small>`;
            list.appendChild(d);
            const o = document.createElement('option'); o.value = `my:${k.id}`; o.textContent = `🔐 ${k.name} (Me)`;
            sel.appendChild(o);
        });

        contacts.forEach(c => {
            const d = document.createElement('div'); d.className = 'pgp-key-item';
            d.innerHTML = `<strong>👤 ${c.name}</strong>`;
            list.appendChild(d);
            const o = document.createElement('option'); o.value = `contact:${c.name}`; o.textContent = `👤 ${c.name}`;
            sel.appendChild(o);
        });
    }

    // PGP Encrypt
    document.getElementById('pgpEncryptBtn').addEventListener('click', async () => {
        const text = document.getElementById('pgpInput').value.trim();
        const sel = document.getElementById('pgpRecipientSelect');
        const ids = Array.from(sel.selectedOptions).map(o => o.value);
        if (!text) return showMessage('Enter a message!', 'error');
        if (ids.length === 0) return showMessage('Select recipients!', 'error');
        try {
            const encKeys = [];
            for (const id of ids) {
                if (id.startsWith('my:')) {
                    const k = getMyKeys().find(x => x.id === id.split(':')[1]);
                    if (k) encKeys.push(await openpgp.readKey({ armoredKey: k.publicKey }));
                } else if (id.startsWith('contact:')) {
                    const c = getContacts().find(x => x.name === id.split(':')[1]);
                    if (c) encKeys.push(await openpgp.readKey({ armoredKey: c.publicKey }));
                }
            }
            if (encKeys.length === 0) return showMessage('No valid recipients!', 'error');
            const msg = await openpgp.createMessage({ text });
            const encrypted = await openpgp.encrypt({ message: msg, encryptionKeys: encKeys });
            document.getElementById('pgpOutput').value = encrypted;
            document.getElementById('pgpResultSection').style.display = 'block';
            showMessage('PGP encrypted! 🔒', 'success');
        } catch (e) { showMessage('PGP encrypt error: ' + e.message, 'error'); }
    });

    // PGP Decrypt
    document.getElementById('pgpDecryptBtn').addEventListener('click', async () => {
        const text = document.getElementById('pgpInput').value.trim();
        if (!text) return showMessage('Paste a PGP message!', 'error');
        try {
            const myKeys = getMyKeys();
            if (myKeys.length === 0) return showMessage('No PGP keys!', 'error');
            const pk = await openpgp.readPrivateKey({ armoredKey: myKeys[0].privateKey });
            let dk = pk;
            if (myKeys[0].hasPassphrase) {
                const pass = prompt('Enter PGP passphrase:');
                if (pass) dk = await openpgp.decryptKey({ privateKey: pk, passphrase: pass });
            }
            const msg = await openpgp.readMessage({ armoredMessage: text });
            const { data } = await openpgp.decrypt({ message: msg, decryptionKeys: dk });
            document.getElementById('pgpOutput').value = data;
            document.getElementById('pgpResultSection').style.display = 'block';
            showMessage('PGP decrypted! 🔓', 'success');
        } catch (e) { showMessage('PGP decrypt error: ' + e.message, 'error'); }
    });

    // PGP Copy
    document.getElementById('pgpCopyBtn')?.addEventListener('click', async () => {
        const t = document.getElementById('pgpOutput').value;
        if (t) { await navigator.clipboard.writeText(t); showMessage('Copied! 📋', 'success'); }
    });

    // ==================== SETTINGS ====================

    // Theme
    const themeBtn = document.getElementById('toggleThemeBtn');
    const saved = localStorage.getItem('cute-theme');
    if (saved === 'dark') { document.documentElement.classList.add('dark-mode'); themeBtn.textContent = 'Switch to Light Mode ☀️'; }
    themeBtn.addEventListener('click', () => {
        const dark = document.documentElement.classList.toggle('dark-mode');
        themeBtn.textContent = dark ? 'Switch to Light Mode ☀️' : 'Switch to Dark Mode 🌙';
        localStorage.setItem('cute-theme', dark ? 'dark' : 'light');
    });

    // Export Keys
    document.getElementById('exportKeysBtn')?.addEventListener('click', () => {
        const data = { keys: getMyKeys(), contacts: getContacts(), exported: new Date().toISOString() };
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.download = `cute_secure_backup_${Date.now()}.json`;
        a.href = URL.createObjectURL(blob);
        a.click();
        showMessage('Keys exported! 💾', 'success');
    });

    // Import Keys
    document.getElementById('importKeysBtn')?.addEventListener('click', () => document.getElementById('importKeysInput').click());
    document.getElementById('importKeysInput')?.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (ev) => {
            try {
                const data = JSON.parse(ev.target.result);
                if (data.keys) saveMyKeys(data.keys);
                if (data.contacts) saveContacts(data.contacts);
                loadMyPublicKey();
                loadContactsUI();
                refreshPGPKeyList();
                showMessage('Keys imported! 🎉', 'success');
            } catch { showMessage('Invalid backup file!', 'error'); }
        };
        reader.readAsText(file);
    });

    // Reset
    document.getElementById('resetAppBtn')?.addEventListener('click', () => {
        if (confirm('⚠️ Delete ALL keys, contacts, and data?\nThis CANNOT be undone!')) {
            localStorage.clear();
            location.reload();
        }
    });

    // ==================== INIT ====================
    loadMyPublicKey();
    loadContactsUI();
    refreshPGPKeyList();
});

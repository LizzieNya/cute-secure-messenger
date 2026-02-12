document.addEventListener('DOMContentLoaded', async () => {
    loadContacts();
    updateKeyStatus();
    loadMyPublicKey();

    // Tab switching
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.getAttribute('data-tab');
            
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            tabPanes.forEach(pane => {
                pane.classList.remove('active');
                if (pane.id === `${tabId}-tab`) {
                    pane.classList.add('active');
                }
            });
        });
    });

    // Modal functionality
    const exportModal = document.getElementById('exportModal');
    const importModal = document.getElementById('importModal');
    const exportBtn = document.getElementById('exportKeyBtn');
    const importBtn = document.getElementById('importKeyBtn');
    
    // Export key modal
    exportBtn.addEventListener('click', async () => {
        exportModal.style.display = 'block';
        document.getElementById('exportPassword').value = '';
        document.getElementById('exportConfirmPassword').value = '';
        document.getElementById('importStatus').style.display = 'none';
    });
    
    // Import key modal
    importBtn.addEventListener('click', () => {
        importModal.style.display = 'block';
        document.getElementById('importContactName').value = '';
        document.getElementById('importPassword').value = '';
        document.getElementById('importSimpleContactName').value = '';
        document.getElementById('importStatus').style.display = 'none';
        document.getElementById('importVerifiedCheckbox').checked = false;
        document.getElementById('importSimpleVerifiedCheckbox').checked = false;
    });
    
    // Close modals
    document.querySelectorAll('.close').forEach(closeBtn => {
        closeBtn.addEventListener('click', () => {
            exportModal.style.display = 'none';
            importModal.style.display = 'none';
        });
    });
    
    window.addEventListener('click', (event) => {
        if (event.target === exportModal) {
            exportModal.style.display = 'none';
        }
        if (event.target === importModal) {
            importModal.style.display = 'none';
        }
        if (event.target === linkPhoneModal) {
            linkPhoneModal.style.display = 'none';
        }
    });

    // Link Phone functionality
    const linkPhoneModal = document.getElementById('linkPhoneModal');
    const linkPhoneBtn = document.getElementById('linkPhoneBtn');
    const closeLinkPhone = document.getElementById('closeLinkPhone');
    
    linkPhoneBtn.addEventListener('click', async () => {
        linkPhoneModal.style.display = 'block';
        document.getElementById('qrLoading').style.display = 'block';
        document.getElementById('linkQrCode').style.display = 'none';
        document.getElementById('linkOtp').textContent = 'LOADING';
        
        try {
            const { qrCode, otp } = await window.electronAPI.generateMobileLink();
            
            document.getElementById('linkQrCode').src = qrCode;
            document.getElementById('linkQrCode').style.display = 'block';
            document.getElementById('qrLoading').style.display = 'none';
            document.getElementById('linkOtp').textContent = otp;
        } catch (error) {
            console.error('Failed to generate mobile link:', error);
            showMessage('Failed to generate secure link! 😢', 'error');
            linkPhoneModal.style.display = 'none';
        }
    });
    
    closeLinkPhone.addEventListener('click', () => {
        linkPhoneModal.style.display = 'none';
    });

    // Export encrypted key
    document.getElementById('exportEncryptedKeyBtn').addEventListener('click', async () => {
        const password = document.getElementById('exportPassword').value;
        const confirmPassword = document.getElementById('exportConfirmPassword').value;
        
        if (!password) {
            showMessage('Please enter a password! 🔒', 'error');
            return;
        }
        
        if (password !== confirmPassword) {
            showMessage('Passwords do not match! 😢', 'error');
            return;
        }
        
        if (password.length < 4) {
            showMessage('Password must be at least 4 characters! 🔑', 'error');
            return;
        }
        
        try {
            const encryptedKeyData = await window.electronAPI.exportMyKeyEncrypted(password);
            const success = await window.electronAPI.saveFile(encryptedKeyData, 'my_key.keyenc');
            if (success) {
                exportModal.style.display = 'none';
                showMessage('Encrypted key file saved successfully! 🎉', 'success');
            } else {
                showMessage('Failed to save key file! 😢', 'error');
            }
        } catch (error) {
            showMessage(`Export failed: ${error.message}`, 'error');
        }
    });

    // Export simple public key
    document.getElementById('exportSimpleKeyBtn').addEventListener('click', async () => {
        if (confirm('⚠️ Simple export shares your public key without password protection.\nAnyone with this file can add you as a contact.\nContinue?')) {
            try {
                const publicKeyData = await window.electronAPI.exportMyPublicKey();
                const success = await window.electronAPI.saveFile(publicKeyData, 'my_public_key.pubkey');
                if (success) {
                    exportModal.style.display = 'none';
                    showMessage('Public key file saved successfully! 🎉', 'success');
                } else {
                    showMessage('Failed to save key file! 😢', 'error');
                }
            } catch (error) {
                showMessage(`Export failed: ${error.message}`, 'error');
            }
        }
    });

    // Load and import encrypted key
    document.getElementById('loadEncryptedKeyBtn').addEventListener('click', async () => {
        const contactName = document.getElementById('importContactName').value.trim();
        const password = document.getElementById('importPassword').value;
        const verified = document.getElementById('importVerifiedCheckbox').checked;
        
        if (!contactName) {
            showMessage('Please enter your friend\'s name! 👩‍❤️‍👨', 'error');
            return;
        }
        
        if (!password) {
            showMessage('Please enter the password! 🔒', 'error');
            return;
        }
        
        try {
            const encryptedData = await window.electronAPI.loadFile();
            if (encryptedData) {
                const success = await window.electronAPI.importEncryptedKey(encryptedData, password, contactName, verified);
                const statusEl = document.getElementById('importStatus');
                if (success) {
                    statusEl.textContent = `✅ Successfully added ${contactName} to your contacts!`;
                    statusEl.className = 'import-status success';
                    statusEl.style.display = 'block';
                    
                    // Clear form and refresh contacts
                    document.getElementById('importContactName').value = '';
                    document.getElementById('importPassword').value = '';
                    document.getElementById('importVerifiedCheckbox').checked = false;
                    await loadContacts();
                    
                    setTimeout(() => {
                        importModal.style.display = 'none';
                        statusEl.style.display = 'none';
                        showMessage(`Added ${contactName} to your contacts! 🎉`, 'success');
                    }, 2000);
                } else {
                    statusEl.textContent = '❌ Failed to import key - check password and try again';
                    statusEl.className = 'import-status error';
                    statusEl.style.display = 'block';
                }
            }
        } catch (error) {
            const statusEl = document.getElementById('importStatus');
            statusEl.textContent = `❌ Error: ${error.message}`;
            statusEl.className = 'import-status error';
            statusEl.style.display = 'block';
        }
    });

    // Load and import simple public key
    document.getElementById('loadSimpleKeyBtn').addEventListener('click', async () => {
        const contactName = document.getElementById('importSimpleContactName').value.trim();
        const verified = document.getElementById('importSimpleVerifiedCheckbox').checked;
        
        if (!contactName) {
            showMessage('Please enter your friend\'s name! 👩‍❤️‍👨', 'error');
            return;
        }
        
        try {
            const publicKeyData = await window.electronAPI.loadFile();
            if (publicKeyData) {
                const success = await window.electronAPI.importPublicKey(publicKeyData, contactName, verified);
                const statusEl = document.getElementById('importStatus');
                if (success) {
                    statusEl.textContent = `✅ Successfully added ${contactName} to your contacts!`;
                    statusEl.className = 'import-status success';
                    statusEl.style.display = 'block';
                    
                    // Clear form and refresh contacts
                    document.getElementById('importSimpleContactName').value = '';
                    document.getElementById('importSimpleVerifiedCheckbox').checked = false;
                    await loadContacts();
                    
                    setTimeout(() => {
                        importModal.style.display = 'none';
                        statusEl.style.display = 'none';
                        showMessage(`Added ${contactName} to your contacts! 🎉`, 'success');
                    }, 2000);
                } else {
                    statusEl.textContent = '❌ Failed to import public key - invalid format';
                    statusEl.className = 'import-status error';
                    statusEl.style.display = 'block';
                }
            }
        } catch (error) {
            const statusEl = document.getElementById('importStatus');
            statusEl.textContent = `❌ Error: ${error.message}`;
            statusEl.className = 'import-status error';
            statusEl.style.display = 'block';
        }
    });

    // Reset my key (FIXED - with proper UI refresh)
    document.getElementById('resetKeyBtn').addEventListener('click', async () => {
        if (confirm('⚠️ This will make ALL your encrypted messages undecryptable!\nAre you sure you want to reset your keys?')) {
            try {
                console.log('Reset button clicked - starting reset process...');
                const newPublicKey = await window.electronAPI.resetMyKey();
                console.log('Reset completed, new public key received:', newPublicKey ? 'YES' : 'NO');
                
                if (newPublicKey) {
                    console.log('Updating UI with new key...');
                    // Update the public key display
                    document.getElementById('myPublicKey').value = newPublicKey;
                    // Reload contacts (they'll be cleared)
                    await loadContacts();
                    showMessage('Your keys have been reset! 🔑✨', 'success');
                } else {
                    showMessage('Failed to reset keys! 😢', 'error');
                }
            } catch (error) {
                console.error('Reset error:', error);
                showMessage(`Error: ${error.message}`, 'error');
            }
        }
    });

    // Copy my key
    document.getElementById('copyKeyBtn').addEventListener('click', async () => {
        const key = document.getElementById('myPublicKey').value;
        if (key) {
            try {
                const success = await window.electronAPI.copyToClipboard(key);
                if (success) {
                    showMessage('Public key copied to clipboard! 📋', 'success');
                } else {
                    showMessage('Failed to copy key! 😢', 'error');
                }
            } catch (error) {
                showMessage(`Error: ${error.message}`, 'error');
            }
        }
    });

    // Export public key button
    document.getElementById('exportPublicKeyBtn').addEventListener('click', () => {
        exportModal.style.display = 'block';
    });

    // Add contact (manual)
    document.getElementById('addContactFormBtn').addEventListener('click', async () => {
        const name = document.getElementById('newContactName').value.trim();
        const key = document.getElementById('newContactKey').value.trim();
        
        if (!name) {
            showMessage('Please enter a friend\'s name! 💕', 'error');
            return;
        }
        
        if (!key) {
            showMessage('Please paste their key! 🔑', 'error');
            return;
        }

        try {
            const success = await window.electronAPI.addContact(name, key);
            if (success) {
                document.getElementById('newContactName').value = '';
                document.getElementById('newContactKey').value = '';
                await loadContacts();
                showMessage(`Added ${name} to your contacts! 🎉`, 'success');
            } else {
                showMessage('Invalid key or friend already exists! 😢', 'error');
            }
        } catch (error) {
            showMessage(`Error: ${error.message}`, 'error');
        }
    });

    // Encrypt (Multi-recipient)
    document.getElementById('encryptBtn').addEventListener('click', async () => {
        const input = document.getElementById('encryptInput').value.trim();
        const select = document.getElementById('recipientSelect');
        const selectedOptions = Array.from(select.selectedOptions);
        const recipientNames = selectedOptions.map(option => option.value);
        
        if (recipientNames.length === 0) {
            showMessage('Please select at least one friend to send to! 👩‍❤️‍👨', 'error');
            return;
        }
        
        if (!input) {
            showMessage('Please enter a message to send! 💬', 'error');
            return;
        }

        try {
            const results = await window.electronAPI.encryptText(input, recipientNames);
            displayMultiEncryptResults(results);
            
            if (recipientNames.length === 1) {
                showMessage(`Message encrypted for ${recipientNames[0]}! ✨`, 'success');
            } else {
                showMessage(`Message encrypted for ${recipientNames.length} friends! ✨`, 'success');
            }
        } catch (error) {
            showMessage(`Failed to encrypt: ${error.message}`, 'error');
        }
    });

    // Decrypt
    document.getElementById('decryptBtn').addEventListener('click', async () => {
        const input = document.getElementById('decryptInput').value.trim();
        
        if (!input) {
            showMessage('Please enter an encrypted message! 🔐', 'error');
            return;
        }

        try {
            const result = await window.electronAPI.decryptText(input);
            document.getElementById('decryptOutput').value = result;
            showMessage('Message decrypted successfully! 💖', 'success');
        } catch (error) {
            showMessage(`Decryption failed: ${error.message}`, 'error');
        }
    });

    // Copy decrypt result
    document.getElementById('copyDecryptBtn').addEventListener('click', async () => {
        const text = document.getElementById('decryptOutput').value;
        if (text) {
            try {
                const success = await window.electronAPI.copyToClipboard(text);
                if (success) {
                    showMessage('Copied to clipboard! 📋💖', 'success');
                } else {
                    showMessage('Failed to copy! 😢', 'error');
                }
            } catch (error) {
                showMessage(`Error: ${error.message}`, 'error');
            }
        }
    });

    // Save all encrypted messages
    document.getElementById('saveEncryptBtn').addEventListener('click', async () => {
        const resultsContainer = document.getElementById('multiEncryptResults');
        const resultItems = resultsContainer.querySelectorAll('.result-item');
        
        if (resultItems.length === 0) {
            showMessage('No encrypted messages to save! 💾', 'error');
            return;
        }

        // Create combined text
        let combinedText = '';
        resultItems.forEach(item => {
            const recipientElement = item.querySelector('.result-recipient');
            const recipientText = recipientElement.textContent;
            const recipient = recipientText.replace('Message for ', '').replace(':', '');
            const encryptedText = item.querySelector('.result-text').value;
            combinedText += `Message for ${recipient}:\n${encryptedText}\n\n`;
        });

        try {
            const success = await window.electronAPI.saveFile(combinedText, 'encrypted_messages.txt');
            if (success) {
                showMessage('All messages saved successfully! 🎉', 'success');
            } else {
                showMessage('Failed to save file! 😢', 'error');
            }
        } catch (error) {
            showMessage(`Save failed: ${error.message}`, 'error');
        }
    });

    // Copy all encrypted messages
    document.getElementById('copyAllBtn').addEventListener('click', async () => {
        const resultsContainer = document.getElementById('multiEncryptResults');
        const resultItems = resultsContainer.querySelectorAll('.result-item');
        
        if (resultItems.length === 0) {
            showMessage('No encrypted messages to copy! 💾', 'error');
            return;
        }

        // Create combined text
        let combinedText = '';
        resultItems.forEach(item => {
            const recipientElement = item.querySelector('.result-recipient');
            const recipientText = recipientElement.textContent;
            const recipient = recipientText.replace('Message for ', '').replace(':', '');
            const encryptedText = item.querySelector('.result-text').value;
            combinedText += `Message for ${recipient}:\n${encryptedText}\n\n`;
        });

        try {
            const success = await window.electronAPI.copyToClipboard(combinedText);
            if (success) {
                showMessage('All messages copied to clipboard! 📋💖', 'success');
            } else {
                showMessage('Failed to copy! 😢', 'error');
            }
        } catch (error) {
            showMessage(`Copy failed: ${error.message}`, 'error');
        }
    });

    function displayMultiEncryptResults(results) {
        const container = document.getElementById('multiEncryptResults');
        container.innerHTML = '';
        
        for (const [recipient, encryptedText] of Object.entries(results)) {
            const resultItem = document.createElement('div');
            resultItem.className = 'result-item';
            resultItem.innerHTML = `
                <div class="result-header">
                    <div class="result-recipient">Message for ${recipient}:</div>
                    <button class="result-copy-btn" data-recipient="${recipient}">📋 Copy</button>
                </div>
                <textarea class="result-text" readonly>${encryptedText}</textarea>
            `;
            container.appendChild(resultItem);
        }
        
        // Add event listeners for copy buttons
        container.querySelectorAll('.result-copy-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const recipient = e.target.getAttribute('data-recipient');
                const textArea = e.target.closest('.result-item').querySelector('.result-text');
                const text = textArea.value;
                
                try {
                    const success = await window.electronAPI.copyToClipboard(text);
                    if (success) {
                        showMessage(`Copied message for ${recipient}! 📋💖`, 'success');
                    } else {
                        showMessage('Failed to copy! 😢', 'error');
                    }
                } catch (error) {
                    showMessage(`Error: ${error.message}`, 'error');
                }
            });
        });
    }

    async function loadMyPublicKey() {
        try {
            const key = await window.electronAPI.getMyPublicKey();
            if (key) {
                document.getElementById('myPublicKey').value = key;
            }
        } catch (error) {
            console.error('Failed to load public key:', error);
            showMessage('Failed to load your key! 😢', 'error');
        }
    }

    async function loadContacts() {
        try {
            const contacts = await window.electronAPI.loadContacts();
            
            // Update recipient select (multi-select)
            const recipientSelect = document.getElementById('recipientSelect');
            const currentValue = Array.from(recipientSelect.selectedOptions).map(opt => opt.value);
            recipientSelect.innerHTML = '';
            contacts.forEach(contact => {
                const option = document.createElement('option');
                option.value = contact.name;
                option.textContent = contact.name;
                if (contact.verified) {
                    option.textContent += ' ✅'; // Verified indicator
                }
                if (currentValue.includes(contact.name)) {
                    option.selected = true;
                }
                recipientSelect.appendChild(option);
            });
            
            // Update contacts list with management features
            const container = document.getElementById('contactsContainer');
            if (contacts.length > 0) {
                container.innerHTML = contacts.map(contact => `
                    <div class="contact-card" data-contact="${contact.name}">
                        <div class="contact-avatar">${contact.name.charAt(0).toUpperCase()}</div>
                        <div class="contact-name">${contact.name} ${contact.verified ? '✅' : ''}</div>
                        <div class="contact-verification">${contact.verified ? 'Verified Friend' : 'Unverified'}</div>
                        <div class="contact-actions">
                            <button class="btn-secondary btn-small edit-btn" data-contact="${contact.name}">✏️ Edit</button>
                            <button class="btn-danger btn-small remove-btn" data-contact="${contact.name}">🗑️ Remove</button>
                        </div>
                        <div class="edit-form" id="edit-form-${contact.name}" style="display: none; width: 100%; margin-top: 10px;">
                            <input type="text" id="edit-name-${contact.name}" placeholder="Friend's name..." value="${contact.name}">
                            <textarea id="edit-key-${contact.name}" placeholder="Public key..." readonly>${contact.publicKey}</textarea>
                            <label>
                                <input type="checkbox" id="edit-verified-${contact.name}" ${contact.verified ? 'checked' : ''}> ✅ Verified Friend
                            </label>
                            <button class="btn-primary btn-small save-edit" data-contact="${contact.name}">💾 Save</button>
                            <button class="btn-secondary btn-small cancel-edit" data-contact="${contact.name}">❌ Cancel</button>
                        </div>
                    </div>
                `).join('');
                
                // Add event listeners for edit/remove buttons
                document.querySelectorAll('.edit-btn').forEach(btn => {
                    btn.addEventListener('click', (e) => {
                        const contactName = e.target.getAttribute('data-contact');
                        document.getElementById(`edit-form-${contactName}`).style.display = 'flex';
                    });
                });
                
                document.querySelectorAll('.remove-btn').forEach(btn => {
                    btn.addEventListener('click', async (e) => {
                        const contactName = e.target.getAttribute('data-contact');
                        if (confirm(`Remove ${contactName} from your contacts?`)) {
                            try {
                                const success = await window.electronAPI.removeContact(contactName);
                                if (success) {
                                    await loadContacts();
                                    showMessage(`${contactName} removed from contacts! 👋`, 'success');
                                } else {
                                    showMessage('Failed to remove contact! 😢', 'error');
                                }
                            } catch (error) {
                                showMessage(`Error: ${error.message}`, 'error');
                            }
                        }
                    });
                });
                
                document.querySelectorAll('.save-edit').forEach(btn => {
                    btn.addEventListener('click', async (e) => {
                        const contactName = e.target.getAttribute('data-contact');
                        const newName = document.getElementById(`edit-name-${contactName}`).value.trim();
                        const newKey = document.getElementById(`edit-key-${contactName}`).value.trim();
                        const verified = document.getElementById(`edit-verified-${contactName}`).checked;
                        
                        if (!newName) {
                            showMessage('Please enter a name! 👩‍❤️‍👨', 'error');
                            return;
                        }
                        
                        if (!newKey) {
                            showMessage('Please enter a public key! 🔑', 'error');
                            return;
                        }
                        
                        try {
                            const success = await window.electronAPI.updateContact(contactName, newName, newKey, verified);
                            if (success) {
                                document.getElementById(`edit-form-${contactName}`).style.display = 'none';
                                await loadContacts();
                                showMessage(`Updated ${newName}'s info! 🔧`, 'success');
                            } else {
                                showMessage('Failed to update contact! 😢', 'error');
                            }
                        } catch (error) {
                            showMessage(`Error: ${error.message}`, 'error');
                        }
                    });
                });
                
                document.querySelectorAll('.cancel-edit').forEach(btn => {
                    btn.addEventListener('click', (e) => {
                        const contactName = e.target.getAttribute('data-contact');
                        document.getElementById(`edit-form-${contactName}`).style.display = 'none';
                    });
                });
            } else {
                container.innerHTML = '<p class="no-contacts">No friends added yet! Add your first friend above 💕</p>';
            }
            
        } catch (error) {
            console.error('Failed to load contacts:', error);
            showMessage('Failed to load contacts! 😢', 'error');
        }
    }

    function showMessage(text, type) {
        const messageEl = document.getElementById('message');
        messageEl.textContent = text;
        messageEl.className = `message ${type}`;
        messageEl.style.display = 'block';
        
        setTimeout(() => {
            messageEl.style.display = 'none';
        }, 3000);
    }

    async function updateKeyStatus() {
        try {
            const statusEl = document.getElementById('keyStatus');
            statusEl.textContent = '✨ Ready to send secure messages!';
            statusEl.style.color = '#228B22';
        } catch (error) {
            console.error('Failed to load key status:', error);
        }
    }

    // ==================== STEGANOGRAPHY ====================

    // State for stego images
    let decoyImageData = null;
    let secretImageData = null;
    let stegoDecodeImageData = null;

    // Stego mode toggle
    document.querySelectorAll('.stego-mode-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const mode = btn.getAttribute('data-stego-mode');
            document.querySelectorAll('.stego-mode-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.stego-section').forEach(s => s.classList.remove('active'));
            document.getElementById(`stego-${mode}`).classList.add('active');
        });
    });

    // Helper: load image from file into canvas pixel data
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

    // Setup upload zone (click + drag-and-drop)
    function setupUploadZone(zoneId, inputId, placeholderId, previewId, infoId, onLoad) {
        const zone = document.getElementById(zoneId);
        const input = document.getElementById(inputId);
        const placeholder = document.getElementById(placeholderId);
        const preview = document.getElementById(previewId);

        zone.addEventListener('click', () => input.click());

        zone.addEventListener('dragover', (e) => {
            e.preventDefault();
            zone.classList.add('drag-over');
        });

        zone.addEventListener('dragleave', () => {
            zone.classList.remove('drag-over');
        });

        zone.addEventListener('drop', (e) => {
            e.preventDefault();
            zone.classList.remove('drag-over');
            const file = e.dataTransfer.files[0];
            if (file && file.type.startsWith('image/')) {
                handleFile(file);
            }
        });

        input.addEventListener('change', (e) => {
            if (e.target.files[0]) {
                handleFile(e.target.files[0]);
            }
        });

        async function handleFile(file) {
            try {
                const imgData = await loadImageFromFile(file);
                placeholder.style.display = 'none';
                preview.src = imgData.dataURL;
                preview.style.display = 'block';
                if (infoId) {
                    const infoEl = document.getElementById(infoId);
                    infoEl.textContent = `${imgData.width} × ${imgData.height} px · ${(file.size / 1024).toFixed(1)} KB`;
                }
                onLoad(imgData);
            } catch (err) {
                showMessage('Failed to load image! Try another format. 😢', 'error');
            }
        }
    }

    // Setup encode upload zones
    setupUploadZone('decoyDropZone', 'decoyImageInput', 'decoyPlaceholder', 'decoyPreview', 'decoyInfo', (data) => {
        decoyImageData = data;
        updateStegoCapacity();
        updateEncodeButton();
    });

    setupUploadZone('secretDropZone', 'secretImageInput', 'secretPlaceholder', 'secretPreview', 'secretInfo', (data) => {
        secretImageData = data;
        updateStegoCapacity();
        updateEncodeButton();
    });

    // Setup decode upload zone
    setupUploadZone('stegoDecodeDropZone', 'stegoDecodeInput', 'stegoDecodePlaceholder', 'stegoDecodePreview', null, (data) => {
        stegoDecodeImageData = data;
        document.getElementById('stegoDecodeBtn').disabled = false;
        document.getElementById('stegoDecodeResult').style.display = 'none';
    });

    // LSB Constants
    const BITS_PER_CHANNEL = 2;
    const CHANNELS_USED = 3; // R, G, B (not Alpha)
    const BITS_PER_DECOY_PIXEL = BITS_PER_CHANNEL * CHANNELS_USED; // 6
    const HEADER_BITS = 96; // magic(64) + dataLength(32)
    const MAGIC_NUMBER = 0xC5E0C5E0;
    const MAGIC_NUMBER_2 = 0x57E60827;

    // Populate stego recipient selector alongside contacts
    async function populateStegoRecipients() {
        const select = document.getElementById('stegoRecipientSelect');
        if (!select) return;
        const currentValues = Array.from(select.selectedOptions).map(o => o.value);
        select.innerHTML = '<option value="__SELF__">🔒 Me (For Myself)</option>';
        try {
            const contacts = await window.electronAPI.loadContacts();
            contacts.forEach(c => {
                const opt = document.createElement('option');
                opt.value = c.name;
                opt.textContent = c.name + (c.verified ? ' ✅' : '');
                if (currentValues.includes(c.name)) opt.selected = true;
                select.appendChild(opt);
            });
        } catch (e) { console.error('Failed to load contacts for stego:', e); }
        // Ensure "Me" is selected by default if nothing else is
        if (select.selectedOptions.length === 0) select.options[0].selected = true;
    }
    populateStegoRecipients();

    // Estimate encrypted data size for capacity bar
    function estimateEncryptedSize() {
        if (!secretImageData) return 0;
        // secretImageData.dataURL is the original file as data URL
        const rawLen = secretImageData.dataURL.length;
        // After encryption: AES adds ~16 bytes + JSON envelope ~600 bytes + base64 overhead
        return Math.ceil(rawLen * 1.4) + 800;
    }

    function updateStegoCapacity() {
        const bar = document.getElementById('stegoCapacityBar');
        if (!decoyImageData || !secretImageData) { bar.style.display = 'none'; return; }

        bar.style.display = 'block';
        const totalDecoyPixels = decoyImageData.width * decoyImageData.height;
        const estBytes = estimateEncryptedSize();
        const bitsNeeded = HEADER_BITS + (estBytes * 8);
        const pixelsNeeded = Math.ceil(bitsNeeded / BITS_PER_DECOY_PIXEL);
        const usage = (pixelsNeeded / totalDecoyPixels) * 100;

        const fill = document.getElementById('stegoCapacityFill');
        const text = document.getElementById('stegoCapacityText');
        const detail = document.getElementById('stegoCapacityDetail');

        fill.style.width = Math.min(usage, 100) + '%';
        fill.className = 'stego-capacity-fill';

        if (usage > 100) {
            fill.classList.add('over');
            text.textContent = '❌ Over capacity!';
            detail.textContent = `Estimated ~${(estBytes/1024).toFixed(0)}KB encrypted data won't fit. Use a larger decoy or smaller secret.`;
        } else if (usage > 75) {
            fill.classList.add('warning');
            text.textContent = `~${usage.toFixed(1)}%`;
            detail.textContent = `Estimated ~${(estBytes/1024).toFixed(0)}KB. Tight fit — may work but subtle artifacts possible.`;
        } else {
            text.textContent = `~${usage.toFixed(1)}%`;
            detail.textContent = `Estimated ~${(estBytes/1024).toFixed(0)}KB. Plenty of room!`;
        }
    }

    function updateEncodeButton() {
        const btn = document.getElementById('stegoEncodeBtn');
        const select = document.getElementById('stegoRecipientSelect');
        const hasRecipient = select && select.selectedOptions.length > 0;
        if (!decoyImageData || !secretImageData || !hasRecipient) { btn.disabled = true; return; }

        const totalDecoyPixels = decoyImageData.width * decoyImageData.height;
        const estBytes = estimateEncryptedSize();
        const bitsNeeded = HEADER_BITS + (estBytes * 8);
        const pixelsNeeded = Math.ceil(bitsNeeded / BITS_PER_DECOY_PIXEL);
        btn.disabled = pixelsNeeded > totalDecoyPixels;
    }

    // Update encode button when recipient selection changes
    document.getElementById('stegoRecipientSelect').addEventListener('change', updateEncodeButton);

    // ---- Core LSB Bit Operations ----

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

    // Draw watermark
    function drawWatermark(ctx, canvasWidth, canvasHeight) {
        const size = 14, margin = 4;
        const x = canvasWidth - size - margin, y = canvasHeight - size - margin;
        ctx.save(); ctx.globalAlpha = 0.35;
        ctx.fillStyle = '#FF69B4';
        ctx.beginPath(); ctx.ellipse(x + 4, y + 5, 3.5, 4, -0.3, 0, Math.PI * 2); ctx.fill();
        ctx.beginPath(); ctx.ellipse(x + 10, y + 5, 3.5, 4, 0.3, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = '#C71585';
        ctx.beginPath(); ctx.arc(x + 7, y + 5, 2, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = '#FF69B4';
        ctx.beginPath(); ctx.moveTo(x+5,y+8); ctx.lineTo(x+3,y+13); ctx.lineTo(x+6,y+10); ctx.fill();
        ctx.beginPath(); ctx.moveTo(x+9,y+8); ctx.lineTo(x+11,y+13); ctx.lineTo(x+8,y+10); ctx.fill();
        ctx.restore();
    }

    // ---- Encode: Encrypt + Embed ----

    async function stegoEncode(decoy, secret) {
        const progressFill = document.getElementById('stegoEncodeProgressFill');
        const progressText = document.getElementById('stegoEncodeProgressText');
        document.getElementById('stegoEncodeProgress').style.display = 'block';
        progressFill.style.width = '5%';
        progressText.textContent = 'Encrypting secret image... 🔐';

        // Get selected recipients
        const select = document.getElementById('stegoRecipientSelect');
        const recipientNames = Array.from(select.selectedOptions).map(o => o.value);

        // Encrypt the secret image data URL via IPC
        const encryptedJson = await window.electronAPI.stegoEncryptImage(secret.dataURL, recipientNames);
        const encoder = new TextEncoder();
        const encryptedBytes = encoder.encode(encryptedJson);

        progressFill.style.width = '15%';
        progressText.textContent = `Encrypted ${(encryptedBytes.length / 1024).toFixed(0)}KB. Embedding... 🔮`;

        // Check capacity with actual encrypted data size
        const totalDecoyPixels = decoy.width * decoy.height;
        const bitsNeeded = HEADER_BITS + (encryptedBytes.length * 8);
        const pixelsNeeded = Math.ceil(bitsNeeded / BITS_PER_DECOY_PIXEL);
        if (pixelsNeeded > totalDecoyPixels) {
            document.getElementById('stegoEncodeProgress').style.display = 'none';
            throw new Error(`Encrypted data (${(encryptedBytes.length/1024).toFixed(0)}KB) is too large for this decoy image. Use a larger decoy or smaller secret.`);
        }

        return new Promise((resolve) => {
            const canvas = document.getElementById('stegoOutputCanvas');
            canvas.width = decoy.width;
            canvas.height = decoy.height;
            const ctx = canvas.getContext('2d');

            const decoyImg = new Image();
            decoyImg.onload = () => {
                ctx.drawImage(decoyImg, 0, 0);
                const imageData = ctx.getImageData(0, 0, decoy.width, decoy.height);
                const data = imageData.data;

                // Write header: magic + data length
                let bitOffset = 0;
                bitOffset = writeBits(data, bitOffset, MAGIC_NUMBER, 32);
                bitOffset = writeBits(data, bitOffset, MAGIC_NUMBER_2, 32);
                bitOffset = writeBits(data, bitOffset, encryptedBytes.length, 32);

                progressFill.style.width = '20%';
                progressText.textContent = 'Writing encrypted data... 🔮';

                // Write encrypted bytes in chunks
                let byteIndex = 0;
                const chunkSize = 10000;

                function processChunk() {
                    const end = Math.min(byteIndex + chunkSize, encryptedBytes.length);
                    for (let i = byteIndex; i < end; i++) {
                        bitOffset = writeBits(data, bitOffset, encryptedBytes[i], 8);
                    }
                    byteIndex = end;
                    const progress = 20 + (byteIndex / encryptedBytes.length) * 75;
                    progressFill.style.width = progress + '%';
                    progressText.textContent = `Hiding data... ${Math.round(progress)}% 🔮`;

                    if (byteIndex < encryptedBytes.length) {
                        setTimeout(processChunk, 0);
                    } else {
                        ctx.putImageData(imageData, 0, 0);
                        drawWatermark(ctx, decoy.width, decoy.height);
                        progressFill.style.width = '100%';
                        progressText.textContent = 'Complete! ✨';
                        setTimeout(() => {
                            document.getElementById('stegoEncodeProgress').style.display = 'none';
                            document.getElementById('stegoEncodeResult').style.display = 'block';
                            resolve(canvas);
                        }, 400);
                    }
                }
                setTimeout(processChunk, 10);
            };
            decoyImg.src = decoy.dataURL;
        });
    }

    // ---- Decode: Extract + Decrypt ----

    async function stegoDecode(stegoImg) {
        const progressFill = document.getElementById('stegoDecodeProgressFill');
        const progressText = document.getElementById('stegoDecodeProgressText');
        document.getElementById('stegoDecodeProgress').style.display = 'block';
        progressFill.style.width = '10%';
        progressText.textContent = 'Reading header... 📖';

        return new Promise((resolve, reject) => {
            const tempCanvas = document.createElement('canvas');
            tempCanvas.width = stegoImg.width;
            tempCanvas.height = stegoImg.height;
            const tempCtx = tempCanvas.getContext('2d');

            const img = new Image();
            img.onload = async () => {
                try {
                    tempCtx.drawImage(img, 0, 0);
                    const imageData = tempCtx.getImageData(0, 0, stegoImg.width, stegoImg.height);
                    const data = imageData.data;

                    // Read header
                    let bitOffset = 0, result;
                    result = readBits(data, bitOffset, 32); const magic1 = result.value; bitOffset = result.bitOffset;
                    result = readBits(data, bitOffset, 32); const magic2 = result.value; bitOffset = result.bitOffset;

                    if (magic1 !== MAGIC_NUMBER || magic2 !== MAGIC_NUMBER_2) {
                        document.getElementById('stegoDecodeProgress').style.display = 'none';
                        reject(new Error('No hidden image found! This image doesn\'t contain steganographic data.'));
                        return;
                    }

                    result = readBits(data, bitOffset, 32);
                    const dataLength = result.value; bitOffset = result.bitOffset;

                    if (dataLength <= 0 || dataLength > 50000000) {
                        document.getElementById('stegoDecodeProgress').style.display = 'none';
                        reject(new Error('Invalid data length. The image may be corrupted.'));
                        return;
                    }

                    progressFill.style.width = '20%';
                    progressText.textContent = `Found ${(dataLength/1024).toFixed(0)}KB of encrypted data. Extracting... 🔍`;

                    // Read encrypted bytes in chunks
                    const encryptedBytes = new Uint8Array(dataLength);
                    let byteIndex = 0;
                    const chunkSize = 10000;

                    function processChunk() {
                        const end = Math.min(byteIndex + chunkSize, dataLength);
                        for (let i = byteIndex; i < end; i++) {
                            result = readBits(data, bitOffset, 8);
                            encryptedBytes[i] = result.value;
                            bitOffset = result.bitOffset;
                        }
                        byteIndex = end;
                        const progress = 20 + (byteIndex / dataLength) * 50;
                        progressFill.style.width = progress + '%';
                        progressText.textContent = `Extracting... ${Math.round(progress)}% 🔍`;

                        if (byteIndex < dataLength) {
                            setTimeout(processChunk, 0);
                        } else {
                            finishDecode();
                        }
                    }

                    async function finishDecode() {
                        try {
                            progressFill.style.width = '75%';
                            progressText.textContent = 'Decrypting with your private key... 🔓';

                            const decoder = new TextDecoder();
                            const encryptedJson = decoder.decode(encryptedBytes);

                            // Decrypt via IPC
                            const imageDataUrl = await window.electronAPI.stegoDecryptImage(encryptedJson);

                            progressFill.style.width = '90%';
                            progressText.textContent = 'Rendering secret image... 🎨';

                            // Display the decrypted image
                            const outputCanvas = document.getElementById('stegoDecodeOutputCanvas');
                            const secretImg = new Image();
                            secretImg.onload = () => {
                                outputCanvas.width = secretImg.width;
                                outputCanvas.height = secretImg.height;
                                const outCtx = outputCanvas.getContext('2d');
                                outCtx.drawImage(secretImg, 0, 0);

                                progressFill.style.width = '100%';
                                progressText.textContent = 'Secret revealed! 🤫';
                                setTimeout(() => {
                                    document.getElementById('stegoDecodeProgress').style.display = 'none';
                                    document.getElementById('stegoDecodeResult').style.display = 'block';
                                    resolve(outputCanvas);
                                }, 400);
                            };
                            secretImg.onerror = () => {
                                document.getElementById('stegoDecodeProgress').style.display = 'none';
                                reject(new Error('Failed to render decrypted image. Data may be corrupted.'));
                            };
                            secretImg.src = imageDataUrl;
                        } catch (err) {
                            document.getElementById('stegoDecodeProgress').style.display = 'none';
                            reject(err);
                        }
                    }

                    setTimeout(processChunk, 10);
                } catch (err) {
                    document.getElementById('stegoDecodeProgress').style.display = 'none';
                    reject(err);
                }
            };
            img.src = stegoImg.dataURL;
        });
    }

    // ---- Button Handlers ----

    // Encode button
    document.getElementById('stegoEncodeBtn').addEventListener('click', async () => {
        if (!decoyImageData || !secretImageData) return;
        document.getElementById('stegoEncodeResult').style.display = 'none';
        try {
            await stegoEncode(decoyImageData, secretImageData);
            showMessage('Secret image encrypted & hidden successfully! 🔮✨', 'success');
        } catch (err) {
            showMessage(`Encoding failed: ${err.message}`, 'error');
            document.getElementById('stegoEncodeProgress').style.display = 'none';
        }
    });

    // Decode button
    document.getElementById('stegoDecodeBtn').addEventListener('click', async () => {
        if (!stegoDecodeImageData) return;
        document.getElementById('stegoDecodeResult').style.display = 'none';
        try {
            await stegoDecode(stegoDecodeImageData);
            showMessage('Secret image decrypted & revealed! 🤫💖', 'success');
        } catch (err) {
            showMessage(err.message, 'error');
            document.getElementById('stegoDecodeProgress').style.display = 'none';
        }
    });

    // Download encode result
    document.getElementById('stegoDownloadBtn').addEventListener('click', () => {
        const canvas = document.getElementById('stegoOutputCanvas');
        canvas.toBlob((blob) => {
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = 'stego_image.png'; a.click();
            URL.revokeObjectURL(url);
            showMessage('Stego image saved! 💾', 'success');
        }, 'image/png');
    });

    // Copy encode result to clipboard
    document.getElementById('stegoCopyBtn').addEventListener('click', async () => {
        try {
            const canvas = document.getElementById('stegoOutputCanvas');
            const dataUrl = canvas.toDataURL('image/png');
            await window.electronAPI.copyImageToClipboard(dataUrl);
            showMessage('Stego image copied to clipboard! 📋✨', 'success');
        } catch (err) {
            showMessage('Failed to copy to clipboard: ' + err.message, 'error');
        }
    });

    // Download decode result
    document.getElementById('stegoDecodeDownloadBtn').addEventListener('click', () => {
        const canvas = document.getElementById('stegoDecodeOutputCanvas');
        canvas.toBlob((blob) => {
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = 'secret_image.png'; a.click();
            URL.revokeObjectURL(url);
            showMessage('Secret image saved! 💾', 'success');
        }, 'image/png');
    });

    // Copy decode result to clipboard
    document.getElementById('stegoDecodeCopyBtn').addEventListener('click', async () => {
        try {
            const canvas = document.getElementById('stegoDecodeOutputCanvas');
            const dataUrl = canvas.toDataURL('image/png');
            await window.electronAPI.copyImageToClipboard(dataUrl);
            showMessage('Secret image copied to clipboard! 📋🤫', 'success');
        } catch (err) {
            showMessage('Failed to copy to clipboard: ' + err.message, 'error');
        }
    });

    // ==================== FILE VAULT ====================

    let vaultFilePath = null;

    const vaultDropZone = document.getElementById('vaultDropZone');
    const vaultFileInput = document.getElementById('vaultFileInput');
    const vaultSelectBtn = document.getElementById('vaultSelectBtn');
    const vaultFileInfo = document.getElementById('vaultFileInfo');
    const vaultEncryptOptions = document.getElementById('vaultEncryptOptions');
    const vaultDecryptOptions = document.getElementById('vaultDecryptOptions');
    const vaultResult = document.getElementById('vaultResult');
    const vaultResultText = document.getElementById('vaultResultText');

    if (vaultSelectBtn) {
        vaultSelectBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            vaultFileInput.click();
        });
    }

    if (vaultDropZone) {
        vaultDropZone.addEventListener('click', () => vaultFileInput.click());
        vaultDropZone.addEventListener('dragover', (e) => { e.preventDefault(); vaultDropZone.classList.add('drag-over'); });
        vaultDropZone.addEventListener('dragleave', () => vaultDropZone.classList.remove('drag-over'));
        vaultDropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            vaultDropZone.classList.remove('drag-over');
            if (e.dataTransfer.files[0]) handleVaultFile(e.dataTransfer.files[0]);
        });
    }

    if (vaultFileInput) {
        vaultFileInput.addEventListener('change', (e) => {
            if (e.target.files[0]) handleVaultFile(e.target.files[0]);
        });
    }

    function handleVaultFile(file) {
        vaultFilePath = file.path;
        vaultFileInfo.textContent = `📄 ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        vaultFileInfo.style.display = 'block';
        vaultResult.style.display = 'none';

        if (file.name.endsWith('.cute')) {
            vaultEncryptOptions.style.display = 'none';
            vaultDecryptOptions.style.display = 'block';
        } else {
            vaultEncryptOptions.style.display = 'block';
            vaultDecryptOptions.style.display = 'none';
            populateVaultRecipients();
        }
    }

    async function populateVaultRecipients() {
        const select = document.getElementById('vaultRecipientSelect');
        if (!select) return;
        select.innerHTML = '';
        try {
            const contacts = await window.electronAPI.loadContacts();
            contacts.forEach(c => {
                const opt = document.createElement('option');
                opt.value = c.name;
                opt.textContent = c.name + (c.verified ? ' ✅' : '');
                select.appendChild(opt);
            });
        } catch (e) { console.error(e); }
    }

    const vaultEncryptBtn = document.getElementById('vaultEncryptBtn');
    if (vaultEncryptBtn) {
        vaultEncryptBtn.addEventListener('click', async () => {
            if (!vaultFilePath) return showMessage('No file selected!', 'error');
            const select = document.getElementById('vaultRecipientSelect');
            const recipients = Array.from(select.selectedOptions).map(o => o.value);
            try {
                vaultEncryptBtn.disabled = true;
                vaultEncryptBtn.textContent = '⏳ Encrypting...';
                const outputPath = await window.electronAPI.encryptFile(vaultFilePath, recipients);
                vaultResult.style.display = 'block';
                vaultResultText.innerHTML = `<strong>✅ File encrypted!</strong><br>Saved to: <code>${outputPath}</code>`;
                showMessage('File encrypted successfully! 🔒', 'success');
            } catch (e) {
                showMessage(`Encryption failed: ${e.message}`, 'error');
            } finally {
                vaultEncryptBtn.disabled = false;
                vaultEncryptBtn.textContent = '🔒 Encrypt File';
            }
        });
    }

    const vaultDecryptBtn = document.getElementById('vaultDecryptBtn');
    if (vaultDecryptBtn) {
        vaultDecryptBtn.addEventListener('click', async () => {
            if (!vaultFilePath) return showMessage('No file selected!', 'error');
            try {
                vaultDecryptBtn.disabled = true;
                vaultDecryptBtn.textContent = '⏳ Decrypting...';
                const outputPath = await window.electronAPI.decryptFile(vaultFilePath);
                vaultResult.style.display = 'block';
                vaultResultText.innerHTML = `<strong>✅ File decrypted!</strong><br>Saved to: <code>${outputPath}</code>`;
                showMessage('File decrypted successfully! 🔓', 'success');
            } catch (e) {
                showMessage(`Decryption failed: ${e.message}`, 'error');
            } finally {
                vaultDecryptBtn.disabled = false;
                vaultDecryptBtn.textContent = '🔓 Decrypt File';
            }
        });
    }

    // ==================== PGP ====================

    const pgpNewKeyBtn = document.getElementById('pgpNewKeyBtn');
    const pgpGenModal = document.getElementById('pgpGenModal');
    const closePgpGen = document.getElementById('closePgpGen');

    if (pgpNewKeyBtn) pgpNewKeyBtn.addEventListener('click', () => { pgpGenModal.style.display = 'block'; });
    if (closePgpGen) closePgpGen.addEventListener('click', () => { pgpGenModal.style.display = 'none'; });

    const pgpGenerateActionBtn = document.getElementById('pgpGenerateActionBtn');
    if (pgpGenerateActionBtn) {
        pgpGenerateActionBtn.addEventListener('click', async () => {
            const name = document.getElementById('pgpGenName').value.trim();
            const email = document.getElementById('pgpGenEmail').value.trim();
            const pass = document.getElementById('pgpGenPass').value;
            if (!name || !email) return showMessage('Name and email required!', 'error');
            try {
                pgpGenerateActionBtn.disabled = true;
                pgpGenerateActionBtn.textContent = '⏳ Generating...';
                await window.electronAPI.pgpGenerateKey(name, email, pass);
                pgpGenModal.style.display = 'none';
                showMessage('PGP Key generated! 🔑', 'success');
                refreshPGPKeyList();
            } catch (e) {
                showMessage(`PGP Key gen failed: ${e.message}`, 'error');
            } finally {
                pgpGenerateActionBtn.disabled = false;
                pgpGenerateActionBtn.textContent = 'Generate Key 🔑';
            }
        });
    }

    async function refreshPGPKeyList() {
        const list = document.getElementById('pgpKeyList');
        const recipientSelect = document.getElementById('pgpRecipientSelect');
        if (!list) return;
        try {
            const myKeys = await window.electronAPI.pgpListMyKeys();
            const contacts = await window.electronAPI.pgpListContacts();
            list.innerHTML = '';
            recipientSelect.innerHTML = '';

            if (myKeys.length === 0 && contacts.length === 0) {
                list.innerHTML = '<p style="color:#aaa; text-align:center;">No keys yet. Generate one!</p>';
                return;
            }

            myKeys.forEach(k => {
                const div = document.createElement('div');
                div.className = 'pgp-key-item';
                div.innerHTML = `<strong>🔐 ${k.name}</strong><br><small>${k.email}</small>`;
                list.appendChild(div);
                const opt = document.createElement('option');
                opt.value = k.id;
                opt.textContent = `🔐 ${k.name} (Me)`;
                recipientSelect.appendChild(opt);
            });

            contacts.forEach(c => {
                const div = document.createElement('div');
                div.className = 'pgp-key-item';
                div.innerHTML = `<strong>👤 ${c.name}</strong><br><small>${c.fingerprint ? c.fingerprint.slice(0,16) + '...' : 'Imported'}</small>`;
                list.appendChild(div);
                const opt = document.createElement('option');
                opt.value = c.id;
                opt.textContent = `👤 ${c.name}`;
                recipientSelect.appendChild(opt);
            });
        } catch (e) { console.error('PGP refresh error:', e); }
    }

    // PGP Encrypt
    const pgpEncryptBtn = document.getElementById('pgpEncryptBtn');
    if (pgpEncryptBtn) {
        pgpEncryptBtn.addEventListener('click', async () => {
            const text = document.getElementById('pgpInput').value.trim();
            const select = document.getElementById('pgpRecipientSelect');
            const recipientIds = Array.from(select.selectedOptions).map(o => o.value);
            if (!text) return showMessage('Enter a message!', 'error');
            if (recipientIds.length === 0) return showMessage('Select at least one recipient!', 'error');
            try {
                const encrypted = await window.electronAPI.pgpEncryptText(text, recipientIds);
                document.getElementById('pgpOutput').value = encrypted;
                document.getElementById('pgpResultSection').style.display = 'block';
                showMessage('PGP message encrypted! 🔒', 'success');
            } catch (e) {
                showMessage(`PGP encrypt error: ${e.message}`, 'error');
            }
        });
    }

    // PGP Decrypt
    const pgpDecryptBtn = document.getElementById('pgpDecryptBtn');
    if (pgpDecryptBtn) {
        pgpDecryptBtn.addEventListener('click', async () => {
            const text = document.getElementById('pgpInput').value.trim();
            if (!text) return showMessage('Paste an encrypted PGP message!', 'error');
            try {
                const myKeys = await window.electronAPI.pgpListMyKeys();
                if (myKeys.length === 0) return showMessage('No PGP keys. Generate one first!', 'error');
                const pass = prompt('Enter passphrase for your PGP key (leave blank if none):');
                const decrypted = await window.electronAPI.pgpDecryptText(text, myKeys[0].id, pass || '');
                document.getElementById('pgpOutput').value = decrypted;
                document.getElementById('pgpResultSection').style.display = 'block';
                showMessage('PGP message decrypted! 🔓', 'success');
            } catch (e) {
                showMessage(`PGP decrypt error: ${e.message}`, 'error');
            }
        });
    }

    // PGP Copy
    const pgpCopyBtn = document.getElementById('pgpCopyBtn');
    if (pgpCopyBtn) {
        pgpCopyBtn.addEventListener('click', async () => {
            const text = document.getElementById('pgpOutput').value;
            if (text) {
                await window.electronAPI.copyToClipboard(text);
                showMessage('Copied! 📋', 'success');
            }
        });
    }

    // Initial PGP load
    refreshPGPKeyList();

    // ==================== SETTINGS ====================

    const toggleThemeBtn = document.getElementById('toggleThemeBtn');
    if (toggleThemeBtn) {
        const savedTheme = localStorage.getItem('cute-theme');
        if (savedTheme === 'dark') {
            document.documentElement.classList.add('dark-mode');
            toggleThemeBtn.textContent = 'Switch to Light Mode ☀️';
        }

        toggleThemeBtn.addEventListener('click', () => {
            const isDark = document.documentElement.classList.toggle('dark-mode');
            toggleThemeBtn.textContent = isDark ? 'Switch to Light Mode ☀️' : 'Switch to Dark Mode 🌙';
            localStorage.setItem('cute-theme', isDark ? 'dark' : 'light');
        });
    }

    const resetAppBtn = document.getElementById('resetAppBtn');
    if (resetAppBtn) {
        resetAppBtn.addEventListener('click', async () => {
            if (confirm('⚠️ This will delete ALL your data including keys, contacts, and PGP keys.\nThis action CANNOT be undone!\n\nAre you absolutely sure?')) {
                try {
                    await window.electronAPI.resetMyKey();
                    localStorage.clear();
                    location.reload();
                } catch (e) {
                    showMessage(`Reset failed: ${e.message}`, 'error');
                }
            }
        });
    }

});


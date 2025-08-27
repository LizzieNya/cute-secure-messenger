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
    exportBtn.addEventListener('click', () => {
        exportModal.style.display = 'block';
        document.getElementById('exportPassword').value = '';
        document.getElementById('exportConfirmPassword').value = '';
    });
    
    // Import key modal
    importBtn.addEventListener('click', () => {
        importModal.style.display = 'block';
        document.getElementById('importContactName').value = '';
        document.getElementById('importPassword').value = '';
        document.getElementById('importStatus').style.display = 'none';
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
    });

    // Export key file
    document.getElementById('exportKeyFileBtn').addEventListener('click', async () => {
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

    // Load and import key file
    document.getElementById('loadKeyFileBtn').addEventListener('click', async () => {
        const contactName = document.getElementById('importContactName').value.trim();
        const password = document.getElementById('importPassword').value;
        
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
                const success = await window.electronAPI.importEncryptedKey(encryptedData, password, contactName);
                const statusEl = document.getElementById('importStatus');
                if (success) {
                    statusEl.textContent = `✅ Successfully added ${contactName} to your contacts!`;
                    statusEl.className = 'import-status success';
                    statusEl.style.display = 'block';
                    
                    // Clear form and refresh contacts
                    document.getElementById('importContactName').value = '';
                    document.getElementById('importPassword').value = '';
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

    // Reset my key
    document.getElementById('resetKeyBtn').addEventListener('click', async () => {
        if (confirm('⚠️ This will make messages sent TO you undecryptable!\nAre you sure you want to reset your key?')) {
            try {
                const newKey = await window.electronAPI.resetMyKey();
                if (newKey) {
                    await loadMyPublicKey();
                    await loadContacts();
                    showMessage('Your key has been reset! 🔑✨', 'success');
                } else {
                    showMessage('Failed to reset key! 😢', 'error');
                }
            } catch (error) {
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
                    showMessage('Key copied to clipboard! 📋', 'success');
                } else {
                    showMessage('Failed to copy key! 😢', 'error');
                }
            } catch (error) {
                showMessage(`Error: ${error.message}`, 'error');
            }
        }
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

        // Create combined text (FIXED - no double colons)
        let combinedText = '';
        resultItems.forEach(item => {
            const recipientElement = item.querySelector('.result-recipient');
            const recipientText = recipientElement.textContent;
            // Extract recipient name (everything after "Message for " and before ":")
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

    // Copy all encrypted messages (FIXED - no double colons)
    document.getElementById('copyAllBtn').addEventListener('click', async () => {
        const resultsContainer = document.getElementById('multiEncryptResults');
        const resultItems = resultsContainer.querySelectorAll('.result-item');
        
        if (resultItems.length === 0) {
            showMessage('No encrypted messages to copy! 💾', 'error');
            return;
        }

        // Create combined text (FIXED - no double colons)
        let combinedText = '';
        resultItems.forEach(item => {
            const recipientElement = item.querySelector('.result-recipient');
            const recipientText = recipientElement.textContent;
            // Extract recipient name (everything after "Message for " and before ":")
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
                        <div class="contact-name">${contact.name}</div>
                        <div class="contact-actions">
                            <button class="btn-secondary btn-small edit-btn" data-contact="${contact.name}">✏️ Edit</button>
                            <button class="btn-danger btn-small remove-btn" data-contact="${contact.name}">🗑️ Remove</button>
                        </div>
                        <div class="edit-form" id="edit-form-${contact.name}" style="display: none; width: 100%; margin-top: 10px;">
                            <input type="text" id="edit-key-${contact.name}" placeholder="New key..." value="${contact.key}">
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
                        const newKey = document.getElementById(`edit-key-${contactName}`).value.trim();
                        
                        if (!newKey) {
                            showMessage('Please enter a key! 🔑', 'error');
                            return;
                        }
                        
                        try {
                            const success = await window.electronAPI.updateContact(contactName, newKey);
                            if (success) {
                                document.getElementById(`edit-form-${contactName}`).style.display = 'none';
                                await loadContacts();
                                showMessage(`Updated ${contactName}'s key! 🔧`, 'success');
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
});
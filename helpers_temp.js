function getMyPublicKey() {
  const keyPair = loadOrCreateMyKeyPair();
  return keyPair ? keyPair.exportKey('pkcs1-public-pem') : null;
}

function getContactPublicKey(name) {
  if (fs.existsSync(CONTACTS_FILE)) {
    const contacts = JSON.parse(fs.readFileSync(CONTACTS_FILE, 'utf8'));
    const contact = contacts.find(c => c.name === name);
    return contact ? contact.publicKey : null;
  }
  return null;
}

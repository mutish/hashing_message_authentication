document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const senderMessage = document.getElementById('sender-message');
    const senderKey = document.getElementById('sender-key');
    const generateBtn = document.getElementById('generate-btn');
    const calculatedHash = document.getElementById('calculated-hash');
    const encryptedSignature = document.getElementById('encrypted-signature');

    const receivedMessage = document.getElementById('received-message');
    const receivedSignature = document.getElementById('received-signature');
    const receiverKey = document.getElementById('receiver-key');
    const verifyBtn = document.getElementById('verify-btn');
    const recalculatedHash = document.getElementById('recalculated-hash');
    const decryptedHash = document.getElementById('decrypted-hash');
    const statusMatch = document.getElementById('status-match');
    const statusMismatch = document.getElementById('status-mismatch');

    // Store the last payload for verification
    let lastPayload = null;

    // Generate Signature & Transmit
    generateBtn.addEventListener('click', async function() {
        const message = senderMessage.value.trim();
        const key = senderKey.value.trim();

        if (!message || !key) {
            alert('Please enter both a message and a shared secret key.');
            return;
        }

        // Show loading state
        generateBtn.classList.add('loading');
        generateBtn.disabled = true;

        try {
            const response = await fetch('/api/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    message: message,
                    key: key
                })
            });

            if (!response.ok) {
                throw new Error('Failed to generate signature');
            }

            const data = await response.json();
            lastPayload = data;

            // Calculate hash locally for display (from the returned data or compute separately)
            // We'll use a separate endpoint or calculate from the message
            const hashResponse = await fetch('/api/hash', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ message: message })
            });
            
            let hashValue = '';
            if (hashResponse.ok) {
                const hashData = await hashResponse.json();
                hashValue = hashData.hash;
            }

            // Update sender display
            calculatedHash.textContent = hashValue || data.message_hash || '-';
            encryptedSignature.textContent = data.encrypted_hash || '-';

            // Populate receiver fields
            receivedMessage.value = data.message || message;
            receivedSignature.textContent = data.encrypted_hash || '-';

            // Clear previous verification results
            recalculatedHash.textContent = '-';
            decryptedHash.textContent = '-';
            hideStatusBanners();

        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred while generating the signature.');
        } finally {
            generateBtn.classList.remove('loading');
            generateBtn.disabled = false;
        }
    });

    // Decrypt & Verify
    verifyBtn.addEventListener('click', async function() {
        const message = receivedMessage.value.trim();
        const key = receiverKey.value.trim();
        const signature = receivedSignature.textContent.trim();

        if (!message || !key || signature === '-') {
            alert('Please ensure a message has been transmitted and enter the shared secret key.');
            return;
        }

        // Show loading state
        verifyBtn.classList.add('loading');
        verifyBtn.disabled = true;

        try {
            const payload = {
                message: message,
                encrypted_hash: signature
            };

            const response = await fetch('/api/receive', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    payload: payload,
                    key: key
                })
            });

            if (!response.ok) {
                throw new Error('Failed to verify signature');
            }

            const data = await response.json();

            // Update display fields
            recalculatedHash.textContent = data.recalculated_hash || data.current_hash || '-';
            decryptedHash.textContent = data.decrypted_hash || '-';

            // Show appropriate status banner
            hideStatusBanners();
            if (data.authenticated) {
                statusMatch.classList.remove('hidden');
            } else {
                statusMismatch.classList.remove('hidden');
            }

        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred during verification.');
        } finally {
            verifyBtn.classList.remove('loading');
            verifyBtn.disabled = false;
        }
    });

    function hideStatusBanners() {
        statusMatch.classList.add('hidden');
        statusMismatch.classList.add('hidden');
    }
});

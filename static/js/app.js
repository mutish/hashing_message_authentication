/**
 * static/js/app.js
 * Handles frontend interactions for Message Authentication with AES-256-GCM
 */

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
            // Call the /api/send endpoint
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
                throw new Error(`Server error: ${response.status}`);
            }

            const data = await response.json();

            // Update sender display
            calculatedHash.textContent = data.message_hash || '-';
            encryptedSignature.textContent = data.encrypted_hash || '-';

            // Populate receiver fields with transmitted data
            receivedMessage.value = data.message || message;
            receivedSignature.textContent = data.encrypted_hash || '-';

            // Clear previous verification results
            recalculatedHash.textContent = '-';
            decryptedHash.textContent = '-';
            hideStatusBanners();

        } catch (error) {
            console.error('Error:', error);
            alert('Error generating signature: ' + error.message);
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
            // Prepare the payload
            const payload = {
                message: message,
                encrypted_hash: signature
            };

            // Call the /api/receive endpoint
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
                throw new Error(`Server error: ${response.status}`);
            }

            const data = await response.json();

            // Update display fields with results
            recalculatedHash.textContent = data.recalculated_hash || '-';
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
            alert('Error verifying signature: ' + error.message);
        } finally {
            verifyBtn.classList.remove('loading');
            verifyBtn.disabled = false;
        }
    });

    // Helper function to hide status banners
    function hideStatusBanners() {
        statusMatch.classList.add('hidden');
        statusMismatch.classList.add('hidden');
    }
});
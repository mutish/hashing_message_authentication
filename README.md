# Message Authentication with Encrypted Hash

An educational implementation of message authentication using AES-256-GCM encryption. This system demonstrates how to verify message authenticity and integrity by encrypting a SHA-256 hash of the message with a shared symmetric key.

## How It Works

The authentication scheme follows this cryptographic flow:

### Sender Side
1. Compute the SHA-256 hash of the plaintext message: `H(M)`
2. Encrypt the hash using AES-256-GCM with a shared secret key: `E(K, H(M))`
3. Transmit both the plaintext message and encrypted hash to the receiver

### Receiver Side
1. Decrypt the encrypted hash using the shared secret key
2. Recompute the SHA-256 hash of the received message
3. Compare the decrypted hash with the newly computed hash using constant-time comparison
4. If hashes match → message is **authentic and unmodified**
5. If hashes don't match → message was **tampered with or wrong key used**

## Security Features

- **AES-256-GCM**: Authenticated encryption with associated data for both confidentiality and integrity
- **SHA-256**: Cryptographic hash function (256-bit output)
- **Random Nonce**: 12-byte random nonce for each encryption ensures ciphertext uniqueness
- **Constant-Time Comparison**: Prevents timing attacks when comparing hashes
- **Key Derivation**: SHA-256 based key derivation from user-provided passwords to generate cryptographic keys

## Project Structure

```
hashing_message_authentication/
├── app.py                  # Flask web server and REST API endpoints
├── sender.py               # Message hashing and encryption logic
├── receiver.py             # Hash decryption and verification logic
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── templates/
│   └── index.html         # Interactive web interface
└── static/
    ├── css/
    │   └── styles.css     # Frontend styling
    └── js/
        └── app.js         # JavaScript for interactive UI
```

## Setup Instructions

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mutish/hashing_message_authentication.git
   cd hashing_message_authentication
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Web Interface

Run the Flask application:
```bash
python3 app.py
```

The server will start at `http://127.0.0.1:5000`. Open this URL in your browser to access the interactive interface:

- **Source A (Sender)**: Enter a message and shared secret key, then click "Generate Signature & Transmit"
- **Destination B (Receiver)**: The message and encrypted hash are populated automatically. Enter the same shared secret key and click "Decrypt & Verify" to check authenticity
- **Try tampering**: Edit the received message and re-verify to see authentication fail


```bash
# Terminal 1: Start the Flask server
python3 app.py
# Server running at http://127.0.0.1:5000

# Click on the 


```

## Dependencies

- **Flask 3.0.0**: Web framework for building the REST API and serving the web interface
- **cryptography 41.0.4**: Provides AES-256-GCM and other cryptographic primitives

## Learning Outcomes

This project demonstrates:
- Message authentication codes (MAC) concepts
- Symmetric encryption (AES-256-GCM)
- Hash functions (SHA-256)
- Secure key derivation from passwords
- Constant-time comparison to prevent timing attacks
- RESTful API design
- Frontend-backend integration


## Author
Created by Computer Security Group
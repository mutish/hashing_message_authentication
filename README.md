# Hashing and Message Authentication (Part B)
A message authentication scheme where the hash of the message is encrypted using a symmetric key, appended to the plaintext message, and sent to the receiver. The receiver then decrypts the hash, re-hashes the received message, and compares the two to verify authenticity.

## Project Structure
- `app.py`: Flask application and API routing (Copilot generated).
- `sender.py`: Handles hashing and encryption.
- `receiver.py`: Handles decryption and hash comparison.
- `templates/`: Contains `sender.html` and `receiver.html` for the frontend.

## Setup Instructions

1. **Clone the repository.**
2. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
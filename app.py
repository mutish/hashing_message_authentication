import os
from flask import Flask, request, jsonify, render_template
from sender import build_message_payload as generate_secure_payload, generate_hash
from receiver import verify_payload

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/receiver')
def receiver():
    return render_template('receiver.html')


@app.post('/api/send')
def send():
    data = request.get_json()
    if not data or 'message' not in data or 'key' not in data:
        return jsonify({'error': 'Missing required fields: message and key'}), 400
    payload = generate_secure_payload(data['message'], data['key'])
    payload['message_hash'] = generate_hash(data['message'])
    return jsonify(payload)


@app.post('/api/hash')
def hash_message():
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'error': 'Missing required field: message'}), 400
    hash_value = generate_hash(data['message'])
    return jsonify({'hash': hash_value})


@app.post('/api/receive')
def receive():
    data = request.get_json()
    if not data or 'payload' not in data or 'key' not in data:
        return jsonify({'error': 'Missing required fields: payload and key'}), 400
    authenticated, result = verify_payload(data['payload'], data['key'])
    return jsonify({
        'authenticated': authenticated,
        'message': result['extracted_message'],
        'decrypted_hash': result['decrypted_hash'],
        'recalculated_hash': result['recalculated_hash']
    })


if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', 'False') == 'True')

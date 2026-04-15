import os
from flask import Flask, request, jsonify, render_template
from sender import generate_secure_payload
from receiver import verify_payload

app = Flask(__name__)


@app.route('/')
def sender():
    return render_template('sender.html')


@app.route('/receiver')
def receiver():
    return render_template('receiver.html')


@app.post('/api/send')
def send():
    data = request.get_json()
    if not data or 'message' not in data or 'key' not in data:
        return jsonify({'error': 'Missing required fields: message and key'}), 400
    payload = generate_secure_payload(data['message'], data['key'])
    return jsonify(payload)


@app.post('/api/receive')
def receive():
    data = request.get_json()
    if not data or 'payload' not in data or 'key' not in data:
        return jsonify({'error': 'Missing required fields: payload and key'}), 400
    authenticated, message = verify_payload(data['payload'], data['key'])
    return jsonify({'authenticated': authenticated, 'message': message})


if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', 'False') == 'True')

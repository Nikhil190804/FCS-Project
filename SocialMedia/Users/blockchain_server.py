import hashlib
import json
import time
import os
from flask import Flask, request, jsonify

BLOCKCHAIN_FILE = 'blockchain.json'

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_messages = []

        if os.path.exists(BLOCKCHAIN_FILE):
            self.load_chain()
        else:
            self.create_block(previous_hash="1", proof=100)
            self.save_chain()

    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'messages': self.pending_messages,
            'proof': proof,
            'previous_hash': previous_hash,
        }
        self.pending_messages = []
        self.chain.append(block)
        self.save_chain()
        return block

    def add_message(self, sender, message, file_hash=None):
        message_hash = hashlib.sha256(message.encode()).hexdigest()
        entry = {'sender': sender, 'message_hash': message_hash}
        if file_hash:
            entry["file_hash"] = file_hash
        self.pending_messages.append(entry)
        return message_hash

    def get_last_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        while hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()[:4] != "0000":
            new_proof += 1
        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def save_chain(self):
        with open(BLOCKCHAIN_FILE, 'w') as f:
            json.dump(self.chain, f, indent=4)

    def load_chain(self):
        with open(BLOCKCHAIN_FILE, 'r') as f:
            self.chain = json.load(f)

    def is_chain_valid(self, chain):
        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]

            # Recalculate hash of previous block
            previous_block_hash = self.hash(previous_block)
            if current_block['previous_hash'] != previous_block_hash:
                return False

            # Check proof of work
            prev_proof = previous_block['proof']
            current_proof = current_block['proof']
            hash_operation = hashlib.sha256(str(current_proof**2 - prev_proof**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False

        return True

# Flask setup
app = Flask(__name__)
blockchain = Blockchain()

@app.route('/add_message', methods=['POST'])
def add_message():
    data = request.get_json()
    sender = data['sender']
    message = data['message']
    file_hash = data.get('file_hash', None)
    message_hash = blockchain.add_message(sender, message, file_hash)
    return jsonify({'message_hash': message_hash}), 201

@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.get_last_block()
    previous_proof = last_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(proof, previous_hash)
    return jsonify({'message': "Block mined!", 'block': block}), 200

@app.route('/chain', methods=['GET'])
def get_chain():
    return jsonify({'chain': blockchain.chain}), 200

@app.route('/verify_chain', methods=['GET'])
def verify_chain():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        return jsonify({'message': '✅ Blockchain is valid.'}), 200
    else:
        return jsonify({'message': '❌ Blockchain has been tampered with!'}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

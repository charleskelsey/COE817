### Alice - Digital Signature Generation with Nonce
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import socket
import json

# Generate RSA Key Pair for Alice
alice_key = RSA.generate(2048)
alice_public_key = alice_key.publickey().export_key()

def alice():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 12345))
    
    # Step 1: Receive nonce from Bob
    nonce_data = json.loads(client.recv(1024).decode())
    nonce = nonce_data["nonce"]
    
    # Step 2: Create a signed message including the nonce
    message = f"Hello Bob, this is Alice! [Nonce: {nonce}]"
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(alice_key).sign(h)
    
    # Step 3: Send signed message and public key
    client.send(json.dumps({"message": message, "signature": signature.hex(), "public_key": alice_public_key.decode()}).encode())
    print("Sent signed message to Bob with nonce.")
    
    client.close()

if __name__ == "__main__":
    alice()
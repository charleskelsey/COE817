### Bob - Digital Signature Verification with Nonce
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import socket
import json
import secrets

# Generate RSA Key Pair for Bob
bob_key = RSA.generate(2048)
bob_public_key = bob_key.publickey().export_key()

def bob():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 12345))
    server.listen(1)
    print("Bob is waiting for a connection...")
    
    conn, addr = server.accept()
    print("Connected by", addr)
    
    # Step 1: Generate and send nonce to Alice
    nonce = secrets.token_hex(8)
    conn.send(json.dumps({"nonce": nonce}).encode())
    
    # Step 2: Receive signed message from Alice
    raw_data = conn.recv(2048).decode()
    data = json.loads(raw_data)
    message, signature, alice_public_key = data["message"], bytes.fromhex(data["signature"]), data["public_key"]
    
    # Verify nonce inclusion
    if nonce not in message:
        print("Error: Nonce not found in message. Possible replay attack!")
        conn.close()
        return
    
    # Step 3: Verify digital signature
    alice_key = RSA.import_key(alice_public_key)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(alice_key).verify(h, signature)
        print("Signature is valid. Message from Alice:", message)
    except (ValueError, TypeError):
        print("Invalid signature!")
    
    conn.close()

if __name__ == "__main__":
    bob()
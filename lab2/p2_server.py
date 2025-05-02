### Bob - RSA Authentication Server
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import socket
import secrets
import json

# Generate RSA Key Pair for Bob
bob_key = RSA.generate(2048)
bob_public_key = bob_key.publickey().export_key()

# Server (Bob)
def bob():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 12345))
    server.listen(1)
    print("Bob is waiting for a connection...")
    
    conn, addr = server.accept()
    print("Connected by", addr)
    
    # Step 1: Receive Alice's identity and nonce NA
    raw_data = conn.recv(1024).decode()
    data = json.loads(raw_data)
    alice_id, NA = data["id"], data["nonce"]
    print(f"Received message 1 from Alice: ID={alice_id}, NA={NA}")
    
    # Step 2: Generate Bob's nonce NB and encrypt response
    NB = secrets.token_hex(8)
    response = {"id": "Bob", "nonce": NA}
    alice_public_key = RSA.import_key(data["public_key"])
    cipher = PKCS1_OAEP.new(alice_public_key)
    encrypted_response = cipher.encrypt(json.dumps(response).encode())
    
    # Send Bob's public key, nonce NB, and encrypted response
    conn.send(json.dumps({"nonce": NB, "public_key": bob_public_key.decode(), "encrypted": encrypted_response.hex()}).encode())
    print(f"Sent message 2 to Alice: NB={NB}, Encrypted Message 2={encrypted_response.hex()}")
    
    # Step 3: Receive final encrypted message from Alice
    final_data = conn.recv(1024).decode()
    cipher = PKCS1_OAEP.new(bob_key)
    decrypted_final = cipher.decrypt(bytes.fromhex(final_data)).decode()
    print(f"Final message 3 from Alice (Decrypted): {decrypted_final}")
    
    conn.close()

if __name__ == "__main__":
    bob()

### Alice - RSA Authentication Client
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import socket
import secrets
import json

# Generate RSA Key Pair for Alice
alice_key = RSA.generate(2048)
alice_public_key = alice_key.publickey().export_key()

# Client (Alice)
def alice():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 12345))
    
    # Step 1: Send Alice's identity, nonce NA, and public key
    NA = secrets.token_hex(8)
    client.send(json.dumps({"id": "Alice", "nonce": NA, "public_key": alice_public_key.decode()}).encode())
    print(f"Sent message 1 to Bob: ID=Alice, NA={NA}")
    
    # Step 2: Receive Bob's nonce NB, public key, and encrypted message
    response = json.loads(client.recv(2048).decode())
    NB, bob_public_key, encrypted_message = response["nonce"], response["public_key"], bytes.fromhex(response["encrypted"])
    
    bob_public_key = RSA.import_key(bob_public_key)
    cipher = PKCS1_OAEP.new(alice_key)
    decrypted_response = json.loads(cipher.decrypt(encrypted_message).decode())
    print(f"Received message 2 from Bob: NB={NB}, Decrypted Message 2={decrypted_response}")
    
    # Step 3: Send final encrypted message back to Bob
    final_message = json.dumps({"id": "Alice", "nonce": NB})
    cipher = PKCS1_OAEP.new(bob_public_key)
    encrypted_final = cipher.encrypt(final_message.encode())
    client.send(encrypted_final.hex().encode())
    print(f"Sent message 3 to Bob: Encrypted Final Message={encrypted_final.hex()}")
    
    client.close()

if __name__ == "__main__":
    alice()

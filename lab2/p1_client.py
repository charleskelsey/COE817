### alice.py (Client)
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket
import secrets
import json

# Shared Symmetric Key (Must be 16, 24, or 32 bytes for AES)
KAB = b"thisisaverysecur"

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext  # Prepend IV for decryption

def decrypt_message(encrypted_message, key):
    iv = encrypted_message[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted_message[16:]), AES.block_size)
    return decrypted.decode()

# Client (Alice)
def alice():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 12345))
    
    # Step 1: Send Alice's identity and nonce NA
    NA = secrets.token_hex(8)
    client.send(json.dumps({"id": "Alice", "nonce": NA}).encode())
    print(f"Sent message 1 to Bob: ID=Alice, NA={NA}")
    
    # Step 2: Receive Bob's nonce and encrypted message
    raw_response = client.recv(1024).decode()
    if not raw_response:
        print("Error: Received empty response from server.")
        return
    response = json.loads(raw_response)
    NB, encrypted_message = response["nonce"], bytes.fromhex(response["encrypted"])
    decrypted_response = json.loads(decrypt_message(encrypted_message, KAB))
    print(f"Received message 2 from Bob: NB={NB}, Decrypted Message 2={decrypted_response}")
    
    # Step 3: Send final encrypted message back to Bob
    final_message = json.dumps({"id": "Alice", "nonce": NB})
    encrypted_final = encrypt_message(final_message, KAB)
    client.send(encrypted_final.hex().encode())
    print(f"Sent message 3 to Bob: Encrypted Final Message={encrypted_final.hex()}")
    
    client.close()

if __name__ == "__main__":
    alice()

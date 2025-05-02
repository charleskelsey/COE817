### bob.py (Server)
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
    if not raw_data:
        print("Error: Received empty request from Alice.")
        return
    data = json.loads(raw_data)
    alice_id, NA = data["id"], data["nonce"]
    print(f"Received message 1 from Alice: ID={alice_id}, NA={NA}")
    
    # Step 2: Generate Bob's nonce NB
    NB = secrets.token_hex(8)
    response = {"id": "Bob", "nonce": NA}
    encrypted_response = encrypt_message(json.dumps(response), KAB)
    
    # Send Bob's nonce and encrypted message to Alice
    conn.send(json.dumps({"nonce": NB, "encrypted": encrypted_response.hex()}).encode())
    print(f"Sent message 2 to Alice: NB={NB}, Encrypted Message={encrypted_response.hex()}")
    
    # Step 3: Receive final encrypted message from Alice
    final_data = conn.recv(1024).decode()
    decrypted_final = decrypt_message(bytes.fromhex(final_data), KAB)
    print(f"Final message 3 from Alice (Decrypted): {decrypted_final}")
    
    conn.close()

if __name__ == "__main__":
    bob()
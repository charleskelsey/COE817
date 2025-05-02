import socket
import threading
import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 65431

# ----------------------------
# 1) Generate RSA key pair for KDC
# ----------------------------
kdc_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
kdc_public_key = kdc_private_key.public_key()

# Convert keys to PEM strings
kdc_private_pem = kdc_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode()

kdc_public_pem = kdc_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

IDK = "KDC"  # KDC’s identifier

# ----------------------------
# 2) Generate nonces NK1, NK2
#    and master keys KA, KB as valid Fernet keys
# ----------------------------
NK1 = os.urandom(8)  # 8 bytes for nonce
NK2 = os.urandom(8)

# IMPORTANT CHANGE: Use Fernet.generate_key() instead of os.urandom(16)
KA = Fernet.generate_key()  # a 44-byte base64 string
KB = Fernet.generate_key()

print("=== KDC Phase 1 Initialization ===")
print(f"IDK = {IDK}")
print("PUK (KDC's public key) PEM:\n", kdc_public_pem)
print("PRK (KDC's private key) PEM (truncated):\n",
      kdc_private_pem[:200], "...")
print(f"NK1 = {NK1.hex()}")
print(f"NK2 = {NK2.hex()}")
# KA and KB are base64 strings already, so just print them directly
print(f"KA = {KA.decode()}")
print(f"KB = {KB.decode()}")
print("==================================\n")

client_public_keys = {}  # { "A": <PEM string>, "B": <PEM string> }


def rsa_encrypt(pub_key, plaintext: bytes) -> bytes:
    return pub_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def send_json(conn, data: dict):
    message = json.dumps(data).encode()
    conn.sendall(len(message).to_bytes(4, 'big') + message)


def recv_json(conn) -> dict:
    raw_len = conn.recv(4)
    if not raw_len:
        return {}
    msg_len = int.from_bytes(raw_len, 'big')
    data = b''
    while len(data) < msg_len:
        chunk = conn.recv(msg_len - len(data))
        if not chunk:
            break
        data += chunk
    return json.loads(data.decode())


def handle_client(conn):
    try:
        reg = recv_json(conn)
        if reg.get("type") != "register":
            print("[KDC-Phase1] Invalid registration message.")
            return

        cid = reg.get("client_id")
        pub_pem_str = reg.get("public_key", "")
        print(f"[KDC-Phase1] Received registration from client {cid}.")

        # Store the client's public key PEM
        client_public_keys[cid] = pub_pem_str

        # Load the actual public key object
        client_public_key = serialization.load_pem_public_key(
            pub_pem_str.encode())

        # 2) Send the appropriate nonce + IDK to the client
        if cid == "A":
            to_encrypt = {
                "nonce": base64.b64encode(NK1).decode(),
                "idk": IDK
            }
            mk = KA  # This is now a 44-char base64 string
        else:  # cid == "B"
            to_encrypt = {
                "nonce": base64.b64encode(NK2).decode(),
                "idk": IDK
            }
            mk = KB

        enc_nonce = rsa_encrypt(
            client_public_key, json.dumps(to_encrypt).encode())
        send_json(conn, {
            "type": "nonce_and_idk",
            "payload": base64.b64encode(enc_nonce).decode()
        })
        print(f"[KDC-Phase1] Sent nonce + IDK to {cid}.")

        # 3) Send the master key (KA or KB), encrypted with the client's public key
        #    mk is already a base64 string, but we can treat it like bytes for RSA encryption.
        enc_mk = rsa_encrypt(client_public_key, mk)
        send_json(conn, {
            "type": "master_key",
            "payload": base64.b64encode(enc_mk).decode()
        })
        print(f"[KDC-Phase1] Sent master key to {cid}.\n")

    except Exception as e:
        print("[KDC-Phase1] Error handling client:", e)
    finally:
        conn.close()


def main():
    print(f"[KDC-Phase1] Starting server on {HOST}:{PORT} ...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(2)
        print("[KDC-Phase1] Waiting for 2 clients (A and B) to register...")

        threads = []
        for _ in range(2):
            conn, addr = s.accept()
            print(f"[KDC-Phase1] Accepted connection from {addr}")
            t = threading.Thread(target=handle_client, args=(conn,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    print("[KDC-Phase1] All clients have been handled. Phase 1 is complete.")

    # 4) Write everything to a JSON file
    kdc_data = {
        "IDK": IDK,
        "kdc_private_key": kdc_private_pem,
        "kdc_public_key": kdc_public_pem,
        "NK1": base64.b64encode(NK1).decode(),
        "NK2": base64.b64encode(NK2).decode(),
        # KA, KB are already base64 strings, so just store them as is
        "KA": KA.decode(),
        "KB": KB.decode(),
        "client_public_keys": client_public_keys
    }

    with open("kdc_phase1_data.json", "w") as f:
        json.dump(kdc_data, f, indent=2)

    print("[KDC-Phase1] Wrote keys/nonces to kdc_phase1_data.json.\n")


if __name__ == "__main__":
    main()

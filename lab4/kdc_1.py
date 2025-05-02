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

# Generate RSA key pair for KDC
kdc_private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048)
kdc_public_key = kdc_private_key.public_key()

kdc_private_pem = kdc_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode()

kdc_public_pem = kdc_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

IDK = "KDC"

# We generate 3 master keys for A, B, C
KA = Fernet.generate_key()
KB = Fernet.generate_key()
KC = Fernet.generate_key()

# Nonces for A, B, C
NK1 = os.urandom(8)
NK2 = os.urandom(8)
NK3 = os.urandom(8)

client_public_keys = {}  # e.g. {"A": <PEM>, "B": <PEM>, "C": <PEM>}


def rsa_encrypt(pub_key, plaintext: bytes) -> bytes:
    return pub_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def send_json(conn, data):
    msg = json.dumps(data).encode()
    conn.sendall(len(msg).to_bytes(4, 'big') + msg)


def recv_json(conn):
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
        cid = reg["client_id"]
        pub_pem_str = reg["public_key"]
        print(f"[KDC-Phase1] Received registration from client {cid}.")

        client_public_keys[cid] = pub_pem_str
        client_pub_obj = serialization.load_pem_public_key(
            pub_pem_str.encode())

        if cid == "A":
            nonce = NK1
            mk = KA
        elif cid == "B":
            nonce = NK2
            mk = KB
        elif cid == "C":
            nonce = NK3
            mk = KC
        else:
            print("[KDC-Phase1] Unknown client ID:", cid)
            return

        # Send nonce + IDK
        to_encrypt = {
            "nonce": base64.b64encode(nonce).decode(),
            "idk": IDK
        }
        enc_nonce = rsa_encrypt(
            client_pub_obj, json.dumps(to_encrypt).encode())
        send_json(conn, {
            "type": "nonce_and_idk",
            "payload": base64.b64encode(enc_nonce).decode()
        })
        print(f"[KDC-Phase1] Sent nonce + IDK to {cid}.")

        # Send master key
        # mk is already 44-char base64
        enc_mk = rsa_encrypt(client_pub_obj, mk)
        send_json(conn, {
            "type": "master_key",
            "payload": base64.b64encode(enc_mk).decode()
        })
        print(f"[KDC-Phase1] Sent master key to {cid}.\n")

    except Exception as e:
        print("[KDC-Phase1] Error:", e)
    finally:
        conn.close()


def main():
    print("[KDC-Phase1] Starting server on", (HOST, PORT))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(3)  # Now we expect 3 clients: A, B, C
        print("[KDC-Phase1] Waiting for 3 clients (A, B, C) to register...")

        threads = []
        for _ in range(3):
            conn, addr = s.accept()
            print("[KDC-Phase1] Accepted connection from", addr)
            t = threading.Thread(target=handle_client, args=(conn,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    # Write data to JSON if you like
    kdc_data = {
        "IDK": IDK,
        "kdc_private_key": kdc_private_pem,
        "kdc_public_key": kdc_public_pem,
        "KA": KA.decode(),
        "KB": KB.decode(),
        "KC": KC.decode(),
        # ...
    }
    with open("kdc_phase1_data.json", "w") as f:
        json.dump(kdc_data, f, indent=2)

    print("[KDC-Phase1] All clients have been handled. Phase 1 is complete.")


if __name__ == "__main__":
    main()

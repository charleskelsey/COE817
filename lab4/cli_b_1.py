import socket
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = '127.0.0.1'
PORT = 65431


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


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def main():
    IDB = "B"

    # ----------------------------
    # Generate RSA key pair for B
    # ----------------------------
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Convert keys to PEM strings
    pub_pem_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    priv_pem_str = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    print("=== Client B Phase 1 ===")
    print(f"IDB = {IDB}")
    print("PUB (Client B's public key) PEM:\n", pub_pem_str[:200], "...")
    print("PRB (Client B's private key) PEM (truncated):\n",
          priv_pem_str[:200], "...\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[ClientB-Phase1] Connected to KDC.")

        # 1) Register with KDC
        reg_msg = {
            "type": "register",
            "client_id": IDB,
            "public_key": pub_pem_str
        }
        send_json(s, reg_msg)
        print("[ClientB-Phase1] Sent registration message.\n")

        # 2) Receive nonce + IDK
        resp = recv_json(s)
        if resp.get("type") == "nonce_and_idk":
            enc_payload_b64 = resp.get("payload")
            enc_payload = base64.b64decode(enc_payload_b64)
            decrypted = rsa_decrypt(private_key, enc_payload)
            data_json = json.loads(decrypted.decode())

            NK2 = base64.b64decode(data_json["nonce"])
            IDK = data_json["idk"]
            print(f"[ClientB-Phase1] Received NK2 = {NK2.hex()}")
            print(f"[ClientB-Phase1] Received IDK = {IDK}\n")
        else:
            print("[ClientB-Phase1] Did not receive valid nonce/IDK message.")
            return

        # 3) Receive master key KB (as a 44-char base64 string)
        resp2 = recv_json(s)
        if resp2.get("type") == "master_key":
            enc_mk_b64 = resp2.get("payload")
            enc_mk = base64.b64decode(enc_mk_b64)
            KB_bytes = rsa_decrypt(private_key, enc_mk)
            # Convert from bytes to string. Should be a 44-char Fernet key.
            KB = KB_bytes.decode()
            print(f"[ClientB-Phase1] Decrypted KB = {KB}\n")
        else:
            print("[ClientB-Phase1] Did not receive valid master key.")
            return

    print("[ClientB-Phase1] Phase 1 complete.")

    # 4) Store data in JSON for Phase 2
    clientB_data = {
        "IDB": IDB,
        "private_key_pem": priv_pem_str,
        "public_key_pem": pub_pem_str,
        "NK2": base64.b64encode(NK2).decode(),
        "KB": KB  # store the Fernet key string directly
    }

    with open("clientB_phase1_data.json", "w") as f:
        json.dump(clientB_data, f, indent=2)

    print("[ClientB-Phase1] Wrote data to clientB_phase1_data.json.")


if __name__ == "__main__":
    main()

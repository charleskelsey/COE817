import socket
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = '127.0.0.1'
PORT = 65431


def send_json(conn, data: dict):
    msg = json.dumps(data).encode()
    conn.sendall(len(msg).to_bytes(4, 'big') + msg)


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
    IDA = "A"

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    pub_pem_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    priv_pem_str = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    print("=== Client A Phase 1 ===")
    print(f"IDA = {IDA}")
    print("PUA (Client A's public key) PEM:\n", pub_pem_str[:200], "...")
    print("PRA (Client A's private key) PEM (truncated):\n",
          priv_pem_str[:200], "...\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[ClientA-Phase1] Connected to KDC.")

        # Register
        reg_msg = {
            "type": "register",
            "client_id": IDA,
            "public_key": pub_pem_str
        }
        send_json(s, reg_msg)
        print("[ClientA-Phase1] Sent registration message.\n")

        # Receive nonce + IDK
        resp = recv_json(s)
        if resp.get("type") == "nonce_and_idk":
            enc_payload_b64 = resp.get("payload")
            enc_payload = base64.b64decode(enc_payload_b64)
            decrypted = rsa_decrypt(private_key, enc_payload)
            data_json = json.loads(decrypted.decode())

            NK1 = base64.b64decode(data_json["nonce"])
            IDK = data_json["idk"]
            print(f"[ClientA-Phase1] Received NK1 = {NK1.hex()}")
            print(f"[ClientA-Phase1] Received IDK = {IDK}\n")
        else:
            print("[ClientA-Phase1] Did not receive valid nonce/IDK message.")
            return

        # Receive master key KA
        resp2 = recv_json(s)
        if resp2.get("type") == "master_key":
            enc_mk_b64 = resp2.get("payload")
            enc_mk = base64.b64decode(enc_mk_b64)
            # This decrypts the base64 string that is your actual Fernet key
            KA_bytes = rsa_decrypt(private_key, enc_mk)
            KA = KA_bytes.decode()  # Convert from bytes to string
            # It's a 44-char base64 Fernet key
            print(f"[ClientA-Phase1] Decrypted KA = {KA}\n")
        else:
            print("[ClientA-Phase1] Did not receive valid master key.")
            return

    print("[ClientA-Phase1] Phase 1 complete.")

    # Store data
    clientA_data = {
        "IDA": IDA,
        "private_key_pem": priv_pem_str,
        "public_key_pem": pub_pem_str,
        "NK1": base64.b64encode(NK1).decode(),
        "KA": KA  # store it as a string
    }

    with open("clientA_phase1_data.json", "w") as f:
        json.dump(clientA_data, f, indent=2)

    print("[ClientA-Phase1] Wrote data to clientA_phase1_data.json.")


if __name__ == "__main__":
    main()

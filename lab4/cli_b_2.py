import socket
import json
import base64
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

HOST = '127.0.0.1'
PORT = 65432

# Load Phase 1 data for B
with open("clientB_phase1_data.json", "r") as f:
    phase1_data = json.load(f)

IDB = phase1_data["IDB"]      # "B"
KB_str = phase1_data["KB"]    # 44-char master key
private_key_pem = phase1_data["private_key_pem"]

# Load B's private RSA key (for signing)
private_key = serialization.load_pem_private_key(
    private_key_pem.encode(),
    password=None
)

# The group key (Ks) once we get it from the KDC
Ks_str = None

# We'll keep a local sequence number for each message we send
seq_num = 0


def send_json(conn, data):
    msg = json.dumps(data).encode()
    conn.sendall(len(msg).to_bytes(4, 'big') + msg)


def recv_json(conn):
    raw_len = conn.recv(4)
    if not raw_len:
        return None
    msg_len = int.from_bytes(raw_len, 'big')
    data = b''
    while len(data) < msg_len:
        chunk = conn.recv(msg_len - len(data))
        if not chunk:
            break
        data += chunk
    return json.loads(data.decode())


def handle_incoming(kdc_socket):
    """Receive messages from KDC: group_key or forwarded chat."""
    global Ks_str
    while True:
        msg = recv_json(kdc_socket)
        if not msg:
            print("[ClientB] Disconnected from KDC.")
            break

        mtype = msg.get("type")
        if mtype == "group_key":
            # Decrypt the group key with KB
            enc_payload_str = msg["payload"]
            fB = Fernet(KB_str)
            plaintext = fB.decrypt(enc_payload_str.encode())
            data_json = json.loads(plaintext.decode())
            Ks_str = data_json["group_key"]
            print(f"[ClientB] Received group key Ks = {Ks_str}\n")

        elif mtype == "chat_forward":
            # Another client’s chat message
            cipher_str = msg["cipher"]
            signature_b64 = msg["signature"]
            sender_id = msg["sender_id"]
            if not Ks_str:
                print("[ClientB] No Ks yet, can't decrypt.")
                continue

            # Decrypt with Ks
            fK = Fernet(Ks_str)
            cipher_bytes = cipher_str.encode()
            plain = fK.decrypt(cipher_bytes)
            data_json = json.loads(plain.decode())
            msg_id = data_json["id"]
            msg_text = data_json["msg"]
            seq_used = data_json.get("seq", "?")

            # (Optional) verify signature
            sig_bytes = base64.b64decode(signature_b64)
            # If you have the sender’s public key, do something like:
            #   sender_pub_key.verify(sig_bytes, plain, ...)

            print(
                f"[ClientB] <From {msg_id}> seq={seq_used}, msg='{msg_text}'")

        else:
            print("[ClientB] Unknown message type:", mtype)


def main():
    print("=== Client B Phase 2 (with seq) ===")
    print(f"IDB = {IDB}, KB = {KB_str[:8]}... (truncated)")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[ClientB] Connected to KDC for Phase 2.")

        # Register for Phase 2
        reg_msg = {
            "type": "phase2_register",
            "client_id": IDB
        }
        send_json(s, reg_msg)

        # Start a thread to handle incoming messages
        threading.Thread(target=handle_incoming,
                         args=(s,), daemon=True).start()

        global seq_num
        while True:
            line = input("Enter message (or 'quit'): ")
            if line.lower() == "quit":
                break

            if not Ks_str:
                print("[ClientB] No Ks yet, cannot send. Wait for group key.")
                continue

            # Build the plaintext JSON, including seq
            seq_num += 1
            data_json = {
                "id": IDB,
                "seq": seq_num,
                "msg": line
            }
            plaintext_bytes = json.dumps(data_json).encode()

            # E(Ks, [IDB, seq, M])
            fK = Fernet(Ks_str)
            cipher_bytes = fK.encrypt(plaintext_bytes)
            cipher_b64 = cipher_bytes.decode()

            # SigB([IDB, seq, M])
            signature = private_key.sign(
                plaintext_bytes,
                asym_padding.PKCS1v15(),
                hashes.SHA256()
            )
            signature_b64 = base64.b64encode(signature).decode()

            # Display protocol (1) from B
            print("\n--- Protocol (1) from B to KDC ---")
            print(f"E(Ks, [IDB, seq, M]) = {cipher_b64}")
            print(f"SigB([IDB, seq, M])  = {signature_b64}")
            print("-----------------------------------\n")

            # Send to KDC
            chat_msg = {
                "type": "chat_message",
                "cipher": cipher_b64,
                "signature": signature_b64,
                "sender_id": IDB
            }
            send_json(s, chat_msg)
            print("[ClientB] Chat message sent to KDC.")

    print("[ClientB] Exiting Phase 2.")


if __name__ == "__main__":
    main()

import socket
import json
import base64
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

HOST = '127.0.0.1'
PORT = 65432

# Load Phase 1 data for A
with open("clientA_phase1_data.json", "r") as f:
    phase1_data = json.load(f)

IDA = phase1_data["IDA"]            # "A"
KA_str = phase1_data["KA"]          # 44-char master key (from KDC in Phase 1)
private_key_pem = phase1_data["private_key_pem"]

# Load A's private RSA key (for signing)
private_key = serialization.load_pem_private_key(
    private_key_pem.encode(),
    password=None
)

Ks_str = None   # Will store the group/session key from the KDC
seq_num = 0     # Local sequence number for replay protection


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
            print("[ClientA] Disconnected from KDC.")
            break

        mtype = msg.get("type")
        if mtype == "group_key":
            # Decrypt the group key with KA
            enc_payload_str = msg["payload"]
            fA = Fernet(KA_str)
            plaintext = fA.decrypt(enc_payload_str.encode())
            data_json = json.loads(plaintext.decode())
            Ks_str = data_json["group_key"]
            print(f"[ClientA] Received group key Ks = {Ks_str}\n")

        elif mtype == "chat_forward":
            # Another client’s chat message
            cipher_str = msg["cipher"]
            signature_b64 = msg["signature"]
            sender_id = msg["sender_id"]
            if not Ks_str:
                print("[ClientA] No Ks yet, can't decrypt.")
                continue

            # Decrypt with Ks
            fK = Fernet(Ks_str)
            cipher_bytes = cipher_str.encode()
            plain = fK.decrypt(cipher_bytes)
            data_json = json.loads(plain.decode())
            msg_id = data_json["id"]
            msg_text = data_json["msg"]
            seq_used = data_json.get("seq", "?")

            # (Optional) verify signature with sender’s public key
            sig_bytes = base64.b64decode(signature_b64)
            # If you have the sender's public key, e.g.:
            #   sender_pub_key.verify(sig_bytes, plain, ...)

            print(
                f"[ClientA] <From {msg_id}> seq={seq_used}, msg='{msg_text}'")

        else:
            print("[ClientA] Unknown message type:", mtype)


def main():
    print("=== Client A Phase 2 (with seq) ===")
    print(f"IDA = {IDA}, KA = {KA_str[:8]}... (truncated)")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[ClientA] Connected to KDC for Phase 2.")

        # Register for Phase 2
        reg_msg = {
            "type": "phase2_register",
            "client_id": IDA
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
                print("[ClientA] No Ks yet, cannot send. Wait for group key.")
                continue

            # Build the plaintext JSON with sequence number
            seq_num += 1
            data_json = {
                "id": IDA,
                "seq": seq_num,
                "msg": line
            }
            plaintext_bytes = json.dumps(data_json).encode()

            # E(Ks, [IDA, seq, M])
            fK = Fernet(Ks_str)
            cipher_bytes = fK.encrypt(plaintext_bytes)
            cipher_b64 = cipher_bytes.decode()

            # SigA([IDA, seq, M])
            signature = private_key.sign(
                plaintext_bytes,
                asym_padding.PKCS1v15(),
                hashes.SHA256()
            )
            signature_b64 = base64.b64encode(signature).decode()

            # Display the message of protocol (1)
            print("\n--- Protocol (1) from A to KDC ---")
            print(f"E(Ks, [IDA, seq, M]) = {cipher_b64}")
            print(f"SigA([IDA, seq, M])  = {signature_b64}")
            print("-----------------------------------\n")

            # Send to KDC
            chat_msg = {
                "type": "chat_message",
                "cipher": cipher_b64,
                "signature": signature_b64,
                "sender_id": IDA
            }
            send_json(s, chat_msg)
            print("[ClientA] Chat message sent to KDC.")

    print("[ClientA] Exiting Phase 2.")


if __name__ == "__main__":
    main()

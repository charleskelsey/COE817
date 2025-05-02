import socket
import json
import base64
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

HOST = '127.0.0.1'
PORT = 65432

# Load Phase 1 data for C
with open("clientC_phase1_data.json", "r") as f:
    phase1_data = json.load(f)

IDC = phase1_data["IDC"]      # "C"
KC_str = phase1_data["KC"]    # 44-char master key
private_key_pem = phase1_data["private_key_pem"]

# Load C's private RSA key (for signing)
private_key = serialization.load_pem_private_key(
    private_key_pem.encode(),
    password=None
)

Ks_str = None  # group key from KDC
seq_num = 0    # local sequence number


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
    global Ks_str
    while True:
        msg = recv_json(kdc_socket)
        if not msg:
            print("[ClientC] Disconnected from KDC.")
            break

        mtype = msg.get("type")
        if mtype == "group_key":
            # Decrypt with KC
            enc_payload_str = msg["payload"]
            fC = Fernet(KC_str)
            plaintext = fC.decrypt(enc_payload_str.encode())
            data_json = json.loads(plaintext.decode())
            Ks_str = data_json["group_key"]
            print(f"[ClientC] Received group key Ks = {Ks_str}\n")

        elif mtype == "chat_forward":
            # Another client’s chat message
            cipher_str = msg["cipher"]
            signature_b64 = msg["signature"]
            sender_id = msg["sender_id"]
            if not Ks_str:
                print("[ClientC] No Ks yet, can't decrypt.")
                continue

            # Decrypt with Ks
            fK = Fernet(Ks_str)
            cipher_bytes = cipher_str.encode()
            plain = fK.decrypt(cipher_bytes)
            data_json = json.loads(plain.decode())
            msg_id = data_json["id"]
            seq_used = data_json.get("seq", "?")
            msg_text = data_json["msg"]

            # (Optional) verify signature
            sig_bytes = base64.b64decode(signature_b64)
            # If you have sender's public key: sender_pub_key.verify(sig_bytes, plain, ...)

            print(
                f"[ClientC] <From {msg_id}> seq={seq_used}, msg='{msg_text}'")

        else:
            print("[ClientC] Unknown message type:", mtype)


def main():
    print("=== Client C Phase 2 (with seq) ===")
    print(f"IDC = {IDC}, KC = {KC_str[:8]}... (truncated)")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[ClientC] Connected to KDC for Phase 2.")

        reg_msg = {
            "type": "phase2_register",
            "client_id": IDC
        }
        send_json(s, reg_msg)

        threading.Thread(target=handle_incoming,
                         args=(s,), daemon=True).start()

        global seq_num
        while True:
            line = input("Enter message (or 'quit'): ")
            if line.lower() == "quit":
                break

            if not Ks_str:
                print("[ClientC] No Ks yet, cannot send. Wait for group key.")
                continue

            seq_num += 1
            data_json = {
                "id": IDC,
                "seq": seq_num,
                "msg": line
            }
            plaintext_bytes = json.dumps(data_json).encode()

            # E(Ks, [IDC, seq, M])
            fK = Fernet(Ks_str)
            cipher_bytes = fK.encrypt(plaintext_bytes)
            cipher_b64 = cipher_bytes.decode()

            # SigC([IDC, seq, M])
            signature = private_key.sign(
                plaintext_bytes,
                asym_padding.PKCS1v15(),
                hashes.SHA256()
            )
            signature_b64 = base64.b64encode(signature).decode()

            # Display the protocol message
            print("\n--- Protocol (1) from C to KDC ---")
            print(f"E(Ks, [IDC, seq, M]) = {cipher_b64}")
            print(f"SigC([IDC, seq, M])  = {signature_b64}")
            print("-----------------------------------\n")

            # Send to KDC
            chat_msg = {
                "type": "chat_message",
                "cipher": cipher_b64,
                "signature": signature_b64,
                "sender_id": IDC
            }
            send_json(s, chat_msg)
            print("[ClientC] Chat message sent to KDC.")

    print("[ClientC] Exiting Phase 2.")


if __name__ == "__main__":
    main()

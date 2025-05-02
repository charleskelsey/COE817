import socket
import threading
import json
import base64
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

HOST = '127.0.0.1'
PORT = 65432

# Load master keys (KA, KB, KC) from Phase 1
with open("kdc_phase1_data.json", "r") as f:
    phase1_data = json.load(f)

KA_str = phase1_data["KA"]  # for A
KB_str = phase1_data["KB"]  # for B
KC_str = phase1_data["KC"]  # for C

# Also load the public keys of A, B, C if we want to verify chat signatures at the KDC
# or we can just forward them. For demonstration, we store them so we can re-distribute if needed.
# Suppose we didn't store them in phase1_data.json, you can store them similarly.

print("=== KDC Phase 2 (Lab 4) ===")
print(f"Loaded KA = {KA_str}")
print(f"Loaded KB = {KB_str}")
print(f"Loaded KC = {KC_str}\n")

# We'll store each client's connection + ID
clients = {}
lock = threading.Lock()

# Once all three are connected, we generate a single group key Ks
Ks = None
Ks_distributed = False


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


def encrypt_with_masterkey(client_id, plaintext_bytes):
    """Encrypt plaintext_bytes with the appropriate master key (KA, KB, or KC)."""
    if client_id == "A":
        f = Fernet(KA_str)
    elif client_id == "B":
        f = Fernet(KB_str)
    elif client_id == "C":
        f = Fernet(KC_str)
    else:
        raise ValueError("Unknown client_id")
    return f.encrypt(plaintext_bytes)


def handle_client(conn, addr):
    global Ks, Ks_distributed
    try:
        # Expect a "phase2_register" message or something similar
        msg = recv_json(conn)
        if not msg:
            return
        cid = msg.get("client_id")
        msg_type = msg.get("type")
        print(
            f"[KDC-Phase2] {cid} connected from {addr}, message type={msg_type}")

        with lock:
            clients[cid] = conn

        # Wait until we have A, B, C in clients
        while True:
            with lock:
                if len(clients) == 3:
                    break
            time.sleep(0.5)

        # Once we have all three, generate Ks if not done
        if not Ks_distributed:
            Ks = Fernet.generate_key()  # single group key
            print("[KDC-Phase2] Generated group key Ks =", Ks.decode())

            # Send Ks to each client, encrypted under KA, KB, KC
            for c_id in ["A", "B", "C"]:
                if c_id in clients:
                    plaintext = json.dumps({"group_key": Ks.decode()}).encode()
                    encrypted = encrypt_with_masterkey(c_id, plaintext)
                    send_json(clients[c_id], {
                        "type": "group_key",
                        "payload": encrypted.decode("ascii")
                    })
                    print(f"[KDC-Phase2] Sent Ks to {c_id}.")
            Ks_distributed = True
            print("[KDC-Phase2] Group key distribution complete.\n")

        # Now remain in a loop to handle chat messages from this client
        while True:
            chat_msg = recv_json(conn)
            if not chat_msg:
                print(f"[KDC-Phase2] {cid} disconnected.")
                break

            if chat_msg.get("type") == "chat_message":
                # The client sends:
                # {
                #   "type": "chat_message",
                #   "cipher": <base64 of E(Ks, [IDA, seq, M])>,
                #   "signature": <base64 of SigA(IDA, seq, M)>,
                #   "sender_id": "A"
                # }
                # We simply forward to the other two clients.
                print(
                    f"[KDC-Phase2] Received chat_message from {cid}, forwarding to others...")
                forward_msg = {
                    "type": "chat_forward",
                    "cipher": chat_msg["cipher"],
                    "signature": chat_msg["signature"],
                    "sender_id": cid
                }
                # send to all other clients
                for other_id, other_conn in clients.items():
                    if other_id != cid:
                        send_json(other_conn, forward_msg)
            else:
                print("[KDC-Phase2] Unknown message type from", cid)

    except Exception as e:
        print("[KDC-Phase2] Error:", e)
    finally:
        conn.close()


def main():
    print(f"[KDC-Phase2] Starting server on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(3)
        print("[KDC-Phase2] Waiting for 3 clients (A, B, C)...")

        threads = []
        for _ in range(3):
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    print("[KDC-Phase2] Done. Chat server shutting down.")


if __name__ == "__main__":
    main()

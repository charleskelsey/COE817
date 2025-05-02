import socket
import threading
import json
import base64
from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 65432

# Load Phase 1 data (KA, KB) from kdc_phase1_data.json
with open("kdc_phase1_data.json", "r") as f:
    phase1_data = json.load(f)

KA_str = phase1_data["KA"]  # 44-char base64 Fernet key from Phase 1
KB_str = phase1_data["KB"]

print("=== KDC Phase 2 ===")
print(f"Loaded KA = {KA_str}")
print(f"Loaded KB = {KB_str}\n")

# We'll store info for each client:
#   requests["A"] = {"conn": <socket>, "other_id": "B"}
#   requests["B"] = {"conn": <socket>}
requests = {}
lock = threading.Lock()


def send_json(conn, data):
    message = json.dumps(data).encode()
    conn.sendall(len(message).to_bytes(4, 'big') + message)


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


def handle_client(conn):
    try:
        # Receive the first message from this client
        msg = recv_json(conn)
        if not msg:
            return

        msg_type = msg.get("type")
        cid = msg.get("client_id")

        if msg_type == "phase2_request":
            # A says: "I want to talk to B"
            other_id = msg.get("other_id")
            print(
                f"[KDC-Phase2] {cid} requests a session key with {other_id}.")

            with lock:
                # Store A's connection and the other ID
                requests[cid] = {
                    "conn": conn,
                    "other_id": other_id
                }

            # Wait until B is also connected
            while True:
                with lock:
                    if other_id in requests:
                        break

            # Both A and B are known. Generate KAB
            KAB = Fernet.generate_key()  # 44-char base64
            print(f"[KDC-Phase2] Generated KAB = {KAB.decode()}")

            # Encrypt [KAB, IDB] under KA
            fA = Fernet(KA_str)
            payload_for_A = {
                "kab": KAB.decode(),
                "id_b": other_id
            }
            # Fernet token as raw bytes (already URL-safe base64 internally)
            token_for_A = fA.encrypt(json.dumps(
                payload_for_A).encode()).decode("ascii")

            # Send to A
            send_json(requests[cid]["conn"], {
                "type": "session_key_for_A",
                "payload": token_for_A
            })
            print("[KDC-Phase2] Sent session_key_for_A to A.\n")

            # Encrypt [KAB, IDA] under KB
            fB = Fernet(KB_str)
            payload_for_B = {
                "kab": KAB.decode(),
                "id_a": cid
            }
            token_for_B = fB.encrypt(json.dumps(
                payload_for_B).encode()).decode("ascii")

            # Send to B
            send_json(requests[other_id]["conn"], {
                "type": "session_key_for_B",
                "payload": token_for_B
            })
            print("[KDC-Phase2] Sent session_key_for_B to B.\n")

        elif msg_type == "phase2_register":
            # B says: "I am B, I'm ready to receive a session key"
            print(f"[KDC-Phase2] {cid} connected for Phase 2.")
            with lock:
                requests[cid] = {"conn": conn}

        else:
            print("[KDC-Phase2] Unknown or invalid message type:", msg_type)

    except Exception as e:
        print("[KDC-Phase2] Error:", e)
    # DO NOT close conn here; wait until after session key distribution.


def main():
    print(f"[KDC-Phase2] Listening on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(2)
        print("[KDC-Phase2] Waiting for connections from A and B...")

        threads = []
        for _ in range(2):
            c, addr = s.accept()
            print("[KDC-Phase2] Accepted connection from", addr)
            t = threading.Thread(target=handle_client, args=(c,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    print("[KDC-Phase2] Done. Session key distribution complete.")


if __name__ == "__main__":
    main()

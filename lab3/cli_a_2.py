import socket
import json
import base64
from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 65432

with open("clientA_phase1_data.json", "r") as f:
    phase1_data = json.load(f)

IDA = phase1_data["IDA"]     # "A"
KA_str = phase1_data["KA"]   # 44-char base64 Fernet key from Phase 1
IDB = "B"                    # We want a session key to talk to B


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


def main():
    print("=== Client A Phase 2 ===")
    print(f"IDA = {IDA}")
    print(f"KA (Fernet key) = {KA_str}")
    print(f"Requesting session key to communicate with IDB = {IDB}\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[ClientA-Phase2] Connected to KDC.")

        # A sends (ID_A, ID_B) in the request
        req_msg = {
            "type": "phase2_request",
            "client_id": IDA,
            "other_id": IDB
        }
        send_json(s, req_msg)
        print("[ClientA-Phase2] Sent (IDA, IDB) to KDC.\n")

        # Expect the KDC to respond with E(KA, [KAB, IDB]) in a message "session_key_for_A"
        resp = recv_json(s)
        if resp and resp.get("type") == "session_key_for_A":
            enc_token_str = resp.get("payload")  # The Fernet token as a string
            f = Fernet(KA_str)
            try:
                # Decrypt
                decrypted_bytes = f.decrypt(enc_token_str.encode())
                data_json = json.loads(decrypted_bytes.decode())
                kab_str = data_json["kab"]   # e.g., the 44-char session key
                id_b = data_json["id_b"]     # "B"
                print("[ClientA-Phase2] Decrypted session key info:")
                print(f"   KAB = {kab_str}")
                print(f"   id_b = {id_b}")
            except Exception as e:
                print("[ClientA-Phase2] Error decrypting with KA:", e)
        else:
            print("[ClientA-Phase2] Did not receive valid session_key_for_A message.")

    print("[ClientA-Phase2] Done.")


if __name__ == "__main__":
    main()

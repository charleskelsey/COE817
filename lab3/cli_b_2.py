import socket
import json
import base64
from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 65432

with open("clientB_phase1_data.json", "r") as f:
    phase1_data = json.load(f)

IDB = phase1_data["IDB"]     # "B"
KB_str = phase1_data["KB"]   # 44-char base64 Fernet key from Phase 1


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
    print("=== Client B Phase 2 ===")
    print(f"IDB = {IDB}")
    print(f"KB (Fernet key) = {KB_str}\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[ClientB-Phase2] Connected to KDC.")

        # B just registers that it is "B" and can receive a session key
        reg_msg = {
            "type": "phase2_register",
            "client_id": IDB
        }
        send_json(s, reg_msg)
        print("[ClientB-Phase2] Sent 'phase2_register' to KDC.\n")

        # Expect the KDC to respond with E(KB, [KAB, IDA]) in a message "session_key_for_B"
        resp = recv_json(s)
        if resp and resp.get("type") == "session_key_for_B":
            enc_token_str = resp.get("payload")  # The Fernet token as a string
            f = Fernet(KB_str)
            try:
                decrypted_bytes = f.decrypt(enc_token_str.encode())
                data_json = json.loads(decrypted_bytes.decode())
                kab_str = data_json["kab"]
                id_a = data_json["id_a"]
                print("[ClientB-Phase2] Decrypted session key info:")
                print(f"   KAB = {kab_str}")
                print(f"   id_a = {id_a}")
            except Exception as e:
                print("[ClientB-Phase2] Error decrypting with KB:", e)
        else:
            print("[ClientB-Phase2] Did not receive valid session_key_for_B message.")

    print("[ClientB-Phase2] Done.")


if __name__ == "__main__":
    main()

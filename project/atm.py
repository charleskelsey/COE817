import socket
import json
import base64
import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

PSK = b"this_is_the_pre_shared_key_123"


def derive_master_secret(psk, client_nonce, server_nonce):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=client_nonce + server_nonce,
        info=b"COE817-BankingProject"
    )
    return hkdf.derive(psk)


def derive_enc_and_mac_keys(master_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"COE817-EncAndMac"
    )
    key_material = hkdf.derive(master_secret)
    enc_key = key_material[:32]
    mac_key = key_material[32:]
    return enc_key, mac_key


def encrypt_and_mac(enc_key, mac_key, plaintext: bytes) -> dict:
    f = Fernet(base64.urlsafe_b64encode(enc_key[:32]))
    ciphertext = f.encrypt(plaintext)
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(ciphertext)
    mac_val = h.finalize()
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "hmac": base64.b64encode(mac_val).decode()
    }


def decrypt_and_verify(enc_key, mac_key, data: dict) -> bytes:
    ciphertext = base64.b64decode(data["ciphertext"])
    mac_val = base64.b64decode(data["hmac"])
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(ciphertext)
    h.verify(mac_val)
    f = Fernet(base64.urlsafe_b64encode(enc_key[:32]))
    plaintext = f.decrypt(ciphertext)
    return plaintext


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 65432))
    print("[Client] Connected to bank server.")

    # 1) send client_nonce
    client_nonce = os.urandom(16)
    msg = {
        "type": "client_nonce",
        "nonce": base64.b64encode(client_nonce).decode()
    }
    s.sendall(json.dumps(msg).encode())

    # 2) receive server_nonce
    data_raw = s.recv(1024)
    data_json = json.loads(data_raw.decode())
    if data_json.get("type") != "server_nonce":
        print("[Client] Invalid server response.")
        s.close()
        return
    server_nonce = base64.b64decode(data_json["nonce"])

    master_secret = derive_master_secret(PSK, client_nonce, server_nonce)
    enc_key, mac_key = derive_enc_and_mac_keys(master_secret)
    print("[Client] Derived enc_key, mac_key from Master Secret.")

    logged_in = False  # local state

    while True:
        if not logged_in:
            # Not logged in: show register, login, or quit
            print("\n--- ATM Menu (Not Logged In) ---")
            print("1) Register")
            print("2) Login")
            print("3) Quit")
            choice = input("Select an option: ").strip()
            if choice == "3":
                break
            if choice == "1":
                username = input("Username: ")
                password = input("Password: ")
                req = {"cmd": "register",
                       "username": username, "password": password}
            elif choice == "2":
                username = input("Username: ")
                password = input("Password: ")
                req = {"cmd": "login", "username": username,
                       "password": password}
            else:
                print("[Client] Invalid choice.")
                continue

            # send request
            req_enc = encrypt_and_mac(
                enc_key, mac_key, json.dumps(req).encode())
            req_enc_json = json.dumps(req_enc).encode()
            s.sendall(len(req_enc_json).to_bytes(4, 'big') + req_enc_json)

            # receive response
            raw_len = s.recv(4)
            if not raw_len:
                print("[Client] Server closed.")
                break
            msg_len = int.from_bytes(raw_len, 'big')
            data_enc = b''
            while len(data_enc) < msg_len:
                chunk = s.recv(msg_len - len(data_enc))
                if not chunk:
                    break
                data_enc += chunk
            resp_json = json.loads(data_enc.decode())
            resp_plain = decrypt_and_verify(enc_key, mac_key, resp_json)
            resp = json.loads(resp_plain.decode())
            print("[Server Response]", resp)
            if resp["status"] == "ok" and req["cmd"] == "login":
                logged_in = True  # We are now logged in
        else:
            # Logged in: show deposit, withdraw, balance, or quit
            print("\n--- ATM Menu (Logged In) ---")
            print("1) Deposit")
            print("2) Withdraw")
            print("3) Balance")
            print("4) Quit")
            choice = input("Select an option: ").strip()
            if choice == "4":
                break
            if choice == "1":
                amount = input("Amount to deposit: ")
                req = {"cmd": "deposit", "amount": amount}
            elif choice == "2":
                amount = input("Amount to withdraw: ")
                req = {"cmd": "withdraw", "amount": amount}
            elif choice == "3":
                req = {"cmd": "balance"}
            else:
                print("[Client] Invalid choice.")
                continue

            # send request
            req_enc = encrypt_and_mac(
                enc_key, mac_key, json.dumps(req).encode())
            req_enc_json = json.dumps(req_enc).encode()
            s.sendall(len(req_enc_json).to_bytes(4, 'big') + req_enc_json)

            # receive response
            raw_len = s.recv(4)
            if not raw_len:
                print("[Client] Server closed.")
                break
            msg_len = int.from_bytes(raw_len, 'big')
            data_enc = b''
            while len(data_enc) < msg_len:
                chunk = s.recv(msg_len - len(data_enc))
                if not chunk:
                    break
                data_enc += chunk
            resp_json = json.loads(data_enc.decode())
            resp_plain = decrypt_and_verify(enc_key, mac_key, resp_json)
            resp = json.loads(resp_plain.decode())
            print("[Server Response]", resp)

    s.close()
    print("[Client] Exiting.")


if __name__ == "__main__":
    main()

import socket
import threading
import json
import base64
import os
import time
import signal
import sys
import pickle

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

# File to store account data
ACCOUNTS_FILE = "accounts.dat"
accounts = {}
accounts_lock = threading.Lock()

PSK = b"this_is_the_pre_shared_key_123"
AUDIT_LOG_FILE = "audit.log"

# Load accounts from file if it exists
def load_accounts():
    global accounts
    try:
        with open(ACCOUNTS_FILE, "rb") as f:
            accounts = pickle.load(f)
        print(f"[Server] Loaded {len(accounts)} accounts from {ACCOUNTS_FILE}")
    except FileNotFoundError:
        print(f"[Server] No accounts file found, starting with empty accounts")
    except Exception as e:
        print(f"[Server] Error loading accounts: {e}")

# Save accounts to file
def save_accounts():
    try:
        with open(ACCOUNTS_FILE, "wb") as f:
            pickle.dump(accounts, f)
        print(f"[Server] Saved {len(accounts)} accounts to {ACCOUNTS_FILE}")
    except Exception as e:
        print(f"[Server] Error saving accounts: {e}")

def derive_master_secret(psk, client_nonce, server_nonce):
    # same as before
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=client_nonce + server_nonce,
        info=b"COE817-BankingProject"
    )
    return hkdf.derive(psk)


def derive_enc_and_mac_keys(master_secret):
    # same as before
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
    # same as before
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
    # same as before
    ciphertext = base64.b64decode(data["ciphertext"])
    mac_val = base64.b64decode(data["hmac"])
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(ciphertext)
    h.verify(mac_val)
    f = Fernet(base64.urlsafe_b64encode(enc_key[:32]))
    plaintext = f.decrypt(ciphertext)
    return plaintext


def append_to_audit_log(audit_enc_key, line_str):
    # same as before
    f = Fernet(base64.urlsafe_b64encode(audit_enc_key[:32]))
    encrypted_line = f.encrypt(line_str.encode())
    with open(AUDIT_LOG_FILE, "ab") as f_out:
        f_out.write(encrypted_line + b"\n")


def handle_client(conn, addr, audit_enc_key):
    try:
        data_raw = conn.recv(1024)
        if not data_raw:
            conn.close()
            return
        data_json = json.loads(data_raw.decode())
        if data_json.get("type") != "client_nonce":
            conn.close()
            return
        client_nonce = base64.b64decode(data_json["nonce"])

        # send server_nonce
        server_nonce = os.urandom(16)
        msg = {
            "type": "server_nonce",
            "nonce": base64.b64encode(server_nonce).decode()
        }
        conn.sendall(json.dumps(msg).encode())

        master_secret = derive_master_secret(PSK, client_nonce, server_nonce)
        enc_key, mac_key = derive_enc_and_mac_keys(master_secret)

        # NEW: Track session state (authenticated? which user?)
        session_state = {
            "authenticated": False,
            "username": None
        }

        while True:
            raw_len = conn.recv(4)
            if not raw_len:
                break
            msg_len = int.from_bytes(raw_len, 'big')
            data_enc = b''
            while len(data_enc) < msg_len:
                chunk = conn.recv(msg_len - len(data_enc))
                if not chunk:
                    break
                data_enc += chunk
            if not data_enc:
                break
            request_json = json.loads(data_enc.decode())
            try:
                plaintext = decrypt_and_verify(enc_key, mac_key, request_json)
            except Exception as e:
                print("[Server] MAC or decrypt failed:", e)
                break
            req = json.loads(plaintext.decode())

            cmd = req.get("cmd")

            if cmd == "register":
                username = req["username"]
                password = req["password"]
                with accounts_lock:
                    if username in accounts:
                        response = {"status": "error",
                                    "message": "User already exists."}
                    else:
                        accounts[username] = {
                            "password": password, "balance": 0.0}
                        save_accounts()  # Save accounts when a new user registers
                        response = {"status": "ok",
                                    "message": "Registered successfully."}
                line_str = f"{username}\tREGISTER\t{time.ctime()}"
                append_to_audit_log(audit_enc_key, line_str)

            elif cmd == "login":
                username = req["username"]
                password = req["password"]
                with accounts_lock:
                    if username not in accounts or accounts[username]["password"] != password:
                        response = {"status": "error",
                                    "message": "Invalid username or password."}
                    else:
                        response = {"status": "ok",
                                    "message": "Login successful."}
                        # Mark session as authenticated
                        session_state["authenticated"] = True
                        session_state["username"] = username
                line_str = f"{username}\tLOGIN\t{time.ctime()}"
                append_to_audit_log(audit_enc_key, line_str)

            elif cmd in ("deposit", "withdraw", "balance"):
                # Check if authenticated
                if not session_state["authenticated"]:
                    response = {"status": "error",
                                "message": "Not logged in. Please login first."}
                else:
                    username = session_state["username"]
                    if cmd == "deposit":
                        amount = float(req["amount"])
                        with accounts_lock:
                            accounts[username]["balance"] += amount
                            new_bal = accounts[username]["balance"]
                            save_accounts()  # Save accounts after balance change
                            response = {
                                "status": "ok", "message": f"Deposited {amount}, new balance = {new_bal}"}
                        line_str = f"{username}\tDEPOSIT {amount}\t{time.ctime()}"
                        append_to_audit_log(audit_enc_key, line_str)

                    elif cmd == "withdraw":
                        amount = float(req["amount"])
                        with accounts_lock:
                            if accounts[username]["balance"] < amount:
                                response = {"status": "error",
                                            "message": "Insufficient funds."}
                            else:
                                accounts[username]["balance"] -= amount
                                new_bal = accounts[username]["balance"]
                                save_accounts()  # Save accounts after balance change
                                response = {
                                    "status": "ok", "message": f"Withdrew {amount}, new balance = {new_bal}"}
                        line_str = f"{username}\tWITHDRAW {amount}\t{time.ctime()}"
                        append_to_audit_log(audit_enc_key, line_str)

                    elif cmd == "balance":
                        with accounts_lock:
                            bal = accounts[username]["balance"]
                        response = {"status": "ok",
                                    "message": f"Balance = {bal}"}
                        line_str = f"{username}\tBALANCE\t{time.ctime()}"
                        append_to_audit_log(audit_enc_key, line_str)

            else:
                response = {"status": "error", "message": "Unknown command."}

            # send response
            resp_plain = json.dumps(response).encode()
            resp_enc = encrypt_and_mac(enc_key, mac_key, resp_plain)
            resp_enc_json = json.dumps(resp_enc).encode()
            conn.sendall(len(resp_enc_json).to_bytes(4, 'big') + resp_enc_json)

    except Exception as e:
        print("[Server] Error in client thread:", e)
    finally:
        conn.close()

# Signal handler for graceful shutdown
def signal_handler(sig, frame):
    print("\n[Server] Shutting down gracefully...")
    save_accounts()  # Save accounts on shutdown
    sys.exit(0)

def main():
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Load existing accounts
    load_accounts()
    
    audit_enc_key = b"ServerAuditEncryptionKeyMustBe32bytes!"
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Add this to ensure the socket can be reused immediately after server restart
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 65432))
    server.listen(5)
    print("[Server] Listening on port 65432...")

    try:
        while True:
            conn, addr = server.accept()
            print(f"[Server] Connection from {addr}")
            t = threading.Thread(target=handle_client,
                                args=(conn, addr, audit_enc_key))
            t.daemon = True  # Set thread as daemon so it terminates when main thread exits
            t.start()
    except KeyboardInterrupt:
        # This is a backup in case signal handler doesn't work
        print("\n[Server] Received keyboard interrupt, shutting down...")
    finally:
        # Save accounts and close server socket
        save_accounts()
        server.close()
        print("[Server] Server shutdown complete.")


if __name__ == "__main__":
    main()
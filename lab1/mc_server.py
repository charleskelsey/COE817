import socket
import threading

def vigenere_cipher(text, key, decrypt=False):
    result = []
    key = key.upper()
    key_len = len(key)
    key_as_int = [ord(i) - 65 for i in key]
    non_alpha_count = 0  # Track non-alphabetic characters
    
    for i, char in enumerate(text):
        if char.isalpha():
            shift = key_as_int[(i - non_alpha_count) % key_len]
            if decrypt:
                value = (ord(char.upper()) - 65 - shift + 26) % 26
            else:
                value = (ord(char.upper()) - 65 + shift) % 26
            result.append(chr(value + 65))
        else:
            # Keep non-alphabetic characters as they are
            result.append(char)
            non_alpha_count += 1

    return ''.join(result)

def handle_client(conn, addr):
    print(f"New connection from {addr}")
    with conn:
        while True:
            data = conn.recv(1024).decode()
            if not data:
                break
            print(f"Encrypted question from {addr}: {data}")
            question = vigenere_cipher(data, "TMU", decrypt=True)
            question = question.strip().upper()  # Normalize the question
            print(f"Decrypted question from {addr}: {question}")

            # Define answers
            answers = {
                "WHO CREATED YOU": "I WAS CREATED BY APPLE.",
                "WHAT DOES SIRI MEAN": "VICTORY AND BEAUTIFUL.",
                "ARE YOU A ROBOT": "I AM A VIRTUAL ASSISTANT."
            }

            # Fetch the answer or default
            answer = answers.get(question, "I DON'T KNOW THAT.")
            encrypted_answer = vigenere_cipher(answer, "TMU")
            conn.sendall(encrypted_answer.encode())

def server():
    HOST = '127.0.0.1'
    PORT = 65432
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("Server is listening for multiple clients...")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

server()
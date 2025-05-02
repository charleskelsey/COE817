import socket

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

def client():
    HOST = '127.0.0.1'
    PORT = 65432
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        while True:
            question = input("You: ")
            if question.lower() == 'exit':
                break
            encrypted_question = vigenere_cipher(question, "TMU")
            s.sendall(encrypted_question.encode())

            data = s.recv(1024).decode()
            print("Encrypted answer received:", data)
            answer = vigenere_cipher(data, "TMU", decrypt=True)
            print("Siri:", answer)

client()
def encrypt(input_message, encryption_key):
    cipher_text = [0]  # c0 is always 0
    for i in range(len(input_message)):
        message_char, key_char = ord(input_message[i]), ord(encryption_key[i])
        cipher_char = message_char ^ ((key_char + cipher_text[i]) % 256)
        cipher_text.append(cipher_char)
    return cipher_text[1:]  # Exclude the initial 0 for the actual ciphertext

def decrypt(cipher_text, decryption_key):
    decrypted_message = ""
    previous_cipher_char = 0  # c0 is always 0
    for i in range(len(cipher_text)):
        cipher_char, key_char = cipher_text[i], ord(decryption_key[i])
        message_char = cipher_char ^ ((key_char + previous_cipher_char) % 256)
        decrypted_message += chr(message_char)
        previous_cipher_char = cipher_char
    return decrypted_message

def main():
    # Example usage
    input_message = "ishallwork"  # 10 character message
    encryption_key = "moreestuff"  # 10 character key

    # Encrypt the message
    cipher_text = encrypt(input_message, encryption_key)
    print(cipher_text)

    # Decrypt the message
    decrypted_message = decrypt(cipher_text, encryption_key)
    print(decrypted_message)

if __name__ == "__main__":
    main()
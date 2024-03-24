import sys
from BitVector import *
import itertools

def EncryptForFun(input_file, output_file, key):
    PassPhrase = "Hopes and dreams of a million years"
    BLOCKSIZE = 16
    numbytes = BLOCKSIZE // 8

    # Reduce the passphrase to a bit array of size BLOCKSIZE:
    bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)
    for i in range(0, len(PassPhrase) // numbytes):
        textstr = PassPhrase[i*numbytes:(i+1)*numbytes]
        bv_iv ^= BitVector(textstring = textstr)

    key = key.strip()

    # Reduce the key to a bit array of size BLOCKSIZE:
    key_bv = BitVector(bitlist = [0]*BLOCKSIZE)
    for i in range(0, len(key) // numbytes):
        keyblock = key[i*numbytes:(i+1)*numbytes]
        key_bv ^= BitVector(textstring = keyblock)

    # Create a bitvector for storing the ciphertext bit array:
    msg_encrypted_bv = BitVector(size = 0)

    # XORing of bit blocks and encryption:
    previous_block = bv_iv
    bv = BitVector(filename = input_file)
    while (bv.more_to_read):
        bv_read = bv.read_bits_from_file(BLOCKSIZE)
        if len(bv_read) < BLOCKSIZE:
            bv_read += BitVector(size = (BLOCKSIZE - len(bv_read)))
        bv_read ^= key_bv
        bv_read ^= previous_block
        previous_block = bv_read.deep_copy()
        msg_encrypted_bv += bv_read

    # Convert the encrypted bitvector into a hex string:
    outputhex = msg_encrypted_bv.get_hex_string_from_bitvector()

    # Write ciphertext bitvector to the output file:
    with open(output_file, 'w') as FILEOUT:
        FILEOUT.write(outputhex)


def DecryptForFun(input_file, output_file, key):
    PassPhrase = "Hopes and dreams of a million years"
    BLOCKSIZE = 16
    numbytes = BLOCKSIZE // 8

    # Reduce the passphrase to a bit array of size BLOCKSIZE:
    bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)
    for i in range(0, len(PassPhrase) // numbytes):
        textstr = PassPhrase[i*numbytes:(i+1)*numbytes]
        bv_iv ^= BitVector(textstring = textstr)

    # Create a bitvector from the ciphertext hex string:
    with open(input_file) as FILEIN:
        hexstring = FILEIN.read()
        hexstring = ''.join(c for c in hexstring if c in '0123456789abcdefABCDEF')  # Remove non-hexadecimal characters
        encrypted_bv = BitVector(hexstring = hexstring)

    key = key.strip()

    # Reduce the key to a bit array of size BLOCKSIZE:
    key_bv = BitVector(bitlist = [0]*BLOCKSIZE)
    for i in range(0, len(key) // numbytes):
        keyblock = key[i*numbytes:(i+1)*numbytes]
        key_bv ^= BitVector(textstring = keyblock)

    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector(size = 0)

    # Carry out differential XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^= previous_decrypted_block
        previous_decrypted_block = temp
        bv ^= key_bv
        msg_decrypted_bv += bv

    # Extract plaintext from the decrypted bitvector:
    outputtext = msg_decrypted_bv.get_text_from_bitvector()

    # Write plaintext to the output file:
    with open(output_file, 'w') as FILEOUT:
        FILEOUT.write(outputtext)


def generate_keys(characters, max_length):
    for key_length in range(1, max_length + 1):
        for key_tuple in itertools.product(characters, repeat=key_length):
            yield ''.join(key_tuple)

def brute_force_attack(cipher_file, decrypted_file, search_phrase='Douglas Adams', max_key_length=16):
   
    characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*(){}:"<>?[];,./`~'
    for key in generate_keys(characters, max_key_length):
        DecryptForFun(cipher_file, decrypted_file, key)
        with open(decrypted_file, 'r') as file:
            decrypted_text = file.read()
            if search_phrase in decrypted_text:
                return key

    return None


# Usage example
key = brute_force_attack('cipher.txt', 'decrypted.txt')
if key is not None:
    print(f'The key is: {key}')
else:
    print('No key found.')
#!/usr/bin/env python3

from DES import *
import sys
 

def main():
    # Script running command:
    # python3 DES_text.py message.txt key.txt encrypted.txt
    # python3 DES_text.py encrypted.txt key.txt decrypted.txt
    
    
    
    if len(sys.argv) != 4:
        print("Usage: python DES_text.py <input_file> <key_file> <output_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    key_file = sys.argv[2]
    output_file = sys.argv[3]
    
    with open(input_file, "r") as f:
        text = f.read()
    
    with open(key_file, "r") as f:
        key = f.read()
    
    if "encrypted" in output_file:
        output = encrypt_text(text, key)
    else:
        output = decrypt_text(text, key)
    
    with open(output_file, "w") as f:
        f.write(output)
    
    

if __name__ == '__main__':
    main()
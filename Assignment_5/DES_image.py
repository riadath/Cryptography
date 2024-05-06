#!/usr/bin/env python3

from DES import *
import sys

# ./DES_image.py image.ppm key.txt image_enc.ppm 

def main():
    if len(sys.argv) != 4:
        print("Usage: python DES_image.py <input_file> <key_file> <output_file>")
        sys.exit(1)
    with open(sys.argv[2], "r") as f:x
        key = f.read()
    
    EBC_encrypt_image(sys.argv[1], key, sys.argv[3])
    

if __name__ == '__main__':
    main()
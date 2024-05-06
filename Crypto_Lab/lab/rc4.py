from BitVector import *
import wave

def rc4(header,key, plaintext):
    # Initialization
    keyLen = len(key)


    S = list(range(256))
    T = list(range(256))
   
    
    for i in range(256):
        S[i] = i
    j = 0
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]
    
    # Output Init
    OUTPUT = open(outputFileName, "wb")
    OUTPUT.write(meta_data)
    # Key-scheduling algorithm
    i = j = 0
    ciphertext = []
    inputLen = len(plaintext)
    currentPos = 0
    while currentPos < inputLen:
        
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        bv = BitVector(intVal=k, size=8)
        currentBytes = plaintext[currentPos:currentPos+8]
        currentPos += 8
        
        bvToappend = bv ^ currentBytes
        
        bvToappend.write_to_file(OUTPUT)

    return bytes(ciphertext)


print("Choose an option: ")
print("1. Encrypt a text file")
print("2. Decrypt a text file")

choice = input("Enter your choice: ")

if choice == '1':
    inputFileName = 'audio.wav'
    outputFileName = 'audio_encrypted.wav'
else:
    inputFileName = 'audio_encrypted.wav'
    outputFileName = 'audio_decrypted.wav'

with open(inputFileName, "rb") as input_file:
    meta_data = input_file.read(44)
    raw_data = input_file.read()
    input_bv = BitVector(rawbytes = raw_data)





# get key from user
key = input('Enter key of 16 ascii charachter: ')
if len(key) != 16:
    print('Key must be 16 charachters')
    exit()



outputText = rc4(meta_data,key, input_bv)




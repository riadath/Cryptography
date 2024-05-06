import sys
from BitVector import * #(A)
import math

if len(sys.argv) != 3: #(B)
    sys.exit("Needs two command-line arguments, one for  the encrypted file and the other for the  vdecrypted output file")
PassPhrase = "Hopes and dreams of a million years" #(C)
BLOCKSIZE = 16 #(D)
numbytes = BLOCKSIZE // 8 #(E)
# Reduce the passphrase to a bit array of size BLOCKSIZE:
bv_iv = BitVector(bitlist = [0]*BLOCKSIZE) #(F)
for i in range(0,len(PassPhrase) // numbytes): #(G)
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes] #(H)
    bv_iv ^= BitVector( textstring = textstr ) #(I)
# Create a bitvector from the ciphertext hex string:
FILEIN = open(sys.argv[1]) #(J)
encrypted_bv = BitVector( hexstring = FILEIN.read() ) #(K)
# Get key from user:

keyString = ""

for x in range(29556, pow(2,16)):
 
    # Reduce the key to a bit array of size BLOCKSIZE:
    key_bv = BitVector(intVal = x,size = BLOCKSIZE) #(P)

    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector( size = 0 ) #(T)
    # Carry out differential XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv #(U)
    for i in range(0, len(encrypted_bv) // BLOCKSIZE): #(V)
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE] #(W)
        temp = bv.deep_copy() #(X)
        bv ^= previous_decrypted_block #(Y)
        previous_decrypted_block = temp #(Z)
        bv ^= key_bv #(a)
        msg_decrypted_bv += bv #(b)
    

    textarr = []
    keyarr =[]
    # Extract plaintext from the decrypted bitvector:
    outputtext = msg_decrypted_bv.get_text_from_bitvector() #(c)
    print(x)
    if "Douglas Adams" in outputtext:
        keyString = key_bv.get_text_from_bitvector()
        textarr.append(outputtext)
        keyarr.append(keyString)
        break
   
        
print(textarr)
print(keyarr)
with open(sys.argv[2], "w") as text_file:
    text_file.write(outputtext)

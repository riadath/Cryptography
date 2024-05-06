from BitVector import *

PassPhrase = "Hopes and dreams of a million years"
BLOCKSIZE = 16 #(D)
numbytes = BLOCKSIZE // 8

# Reduce the passphrase to a bit array of size BLOCKSIZE:
bv_iv = BitVector(bitlist = [0]*BLOCKSIZE) #(F)
for i in range(0,len(PassPhrase) // numbytes): #(G)
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes] #(H)
    bv_iv ^= BitVector( textstring = textstr ) #(I)

# Get key from user:
key = None
key = input("\nEnter key: ") #(K)
key = key.strip() #(M)

# Reduce the key to a bit array of size BLOCKSIZE:
key_bv = BitVector(bitlist = [0]*BLOCKSIZE) #(N)
for i in range(0,len(key) // numbytes): #(O)
    keyblock = key[i*numbytes:(i+1)*numbytes] #(P)
    key_bv ^= BitVector( textstring = keyblock ) #(Q)
# Create a bitvector for storing the ciphertext bit array:
msg_encrypted_bv = BitVector( size = 0 ) #(R)
# Carry out differential XORing of bit blocks and encryption:
previous_block = bv_iv #(S)
bv = BitVector( filename = sys.argv[1] ) #(T)
cr_bv = BitVector(bitstring = "00001101")
while (bv.more_to_read): #(U)
    bv_read = bv.read_bits_from_file(BLOCKSIZE) #(V)
    if len(bv_read) < BLOCKSIZE: #(W)
        bv_read += BitVector(size = (BLOCKSIZE - len(bv_read))) #(X)

    if cr_bv in bv_read:
        [left_half, right_half] = bv_read.divide_into_two()
        if cr_bv in left_half:
            temp_bv= bv.read_bits_from_file(BLOCKSIZE/2) 
            bv_read = temp_bv+ right_half
        elif cr_bv in right_half:
            temp_bv= bv.read_bits_from_file(BLOCKSIZE/2) 
            bv_read =  left_half + temp_bv

    bv_read ^= key_bv #(Y)
    bv_read ^= previous_block #(Z)
  
    previous_block = bv_read.deep_copy() #(a)

    msg_encrypted_bv += bv_read #(b)
    
# Convert the encrypted bitvector into a hex string:

outputhex = msg_encrypted_bv.get_hex_string_from_bitvector() #(c)
print(outputhex)
# Write ciphertext bitvector to the output file:
FILEOUT = open(sys.argv[2], "w") #(d)
FILEOUT.write(outputhex) #(e)
FILEOUT.close()
"""
Name: Reyadath Ullah
Roll: 33 (SH)

The script reads the key and plaintext from files, encodes the plaintext using the Vigenere cipher, decodes it back to plaintext, and then attempts to crack the cipher using the Kasiski examination. The encoded text is written to a file, and the cracked plaintext is also written to a file.

"""



import matplotlib.pyplot as plt
import collections
import math

# Function to encode plaintext using Vigenere cipher
def vignere_encode(plaintext, key):
    plaintext = list(plaintext)
    key = list(key.lower())  # convert key to lowercase
    
    # Convert key to numerical values
    for i in range(len(key)):
        key[i] = ord(key[i]) - 97
    
    # Convert plaintext to numerical values
    for i in range(len(plaintext)):
        plaintext[i] = ord(plaintext[i])
        
    # Perform Vigenere encryption
    for i in range(len(plaintext)):
        plaintext[i] = (plaintext[i] + key[i % len(key)]) % 255
        
        # Handle wraparound for uppercase and lowercase letters
        if plaintext[i] > 90 and plaintext[i] < 97:
            plaintext[i] = ord('a') + (plaintext[i] - 91)
        if plaintext[i] > 122:
            plaintext[i] = ord('A') + (plaintext[i] - 123)
        
    # Convert numerical values back to characters
    for i in range(len(plaintext)):
        plaintext[i] = chr(plaintext[i])

    plaintext = "".join(plaintext)
    return plaintext

# Function to decode ciphertext using Vigenere cipher
def vignere_decode(ciphertext, key):
    ciphertext = list(ciphertext)
    key = list(key.lower())  # convert key to lowercase
    
    # Convert key to numerical values
    for i in range(len(key)):
        key[i] = ord(key[i]) - 97
    
    # Convert ciphertext to numerical values
    for i in range(len(ciphertext)):
        ciphertext[i] = ord(ciphertext[i])
        
    # Perform Vigenere decryption
    for i in range(len(ciphertext)):
        ciphertext[i] = (ciphertext[i] - key[i % len(key)]) % 255
        
        # Handle wraparound for uppercase and lowercase letters
        if ciphertext[i] < 65:
            ciphertext[i] = ord('z') - (64 - ciphertext[i])
        elif ciphertext[i] > 90 and ciphertext[i] < 97:
            ciphertext[i] = ord('Z') - (96 - ciphertext[i])
        
    # Convert numerical values back to characters
    for i in range(len(ciphertext)):
        ciphertext[i] = chr(ciphertext[i])

    ciphertext = "".join(ciphertext)
    return ciphertext


# Function to plot frequency analysis for a given segment
def plot_frequency_analysis(segment, letter_no):
    # Frequency analysis for plotting
    letter_counts = collections.Counter(segment)
    letters, counts = zip(*letter_counts.most_common())
    # sort by letter
    letters = [chr(i) for i in range(97, 123)]
    counts = [letter_counts[letter] for letter in letters]

    # Plotting
    plt.title(f"Letter No: {letter_no} of the key")
    plt.bar(letters, counts)
    plt.show()


# Function to estimate the key length using Kasiski examination
def estimate_key_length(ciphertext):
    # Find repeated substrings
    substrings = {}
    for i in range(len(ciphertext) - 2):
        substring = ciphertext[i : i + 3]
        if substring in substrings:
            substrings[substring].append(i)
        else:
            substrings[substring] = [i]
    
    # Find the distance between the repeated substrings
    distances = {}
    for substring in substrings:
        if len(substrings[substring]) > 1:
            for i in range(1, len(substrings[substring])):
                distance = substrings[substring][i] - substrings[substring][i - 1]
                if distance in distances:
                    distances[distance] += 1
                else:
                    distances[distance] = 1

    # Find the GCD of the distances
    gcd_distances = math.factorial(50)
    for distance in distances:
        if distances[distance] > 1:
            if math.gcd(gcd_distances, distance) > 2:
                gcd_distances = math.gcd(gcd_distances, distance)
    print("GCD Distances:", gcd_distances)
    
    return gcd_distances
            

# Function to perform frequency analysis and guess the key
def frequency_analysis(ciphertext, estimated_key_length):
    segments = [""] * estimated_key_length
    for i, char in enumerate(ciphertext):
        segments[i % estimated_key_length] += char
    key_guess = ""
    for segment in segments:
        segment_freq = collections.Counter(segment)
        segment_freq = dict(sorted(segment_freq.items()))
        # get total letter count
        total_count = sum(segment_freq.values())
        # get frequency of each letter
        segment_freq = {k: v / total_count * 100 for k, v in segment_freq.items()}
        
        # Uncomment the line below to plot frequency analysis for each segment
        # plot_frequency_analysis(segment, segments.index(segment) + 1)
        
        # Get the highest frequency letter
        max_freq, max_freq_letter = 0, ''
        for letter in segment_freq:
            if segment_freq[letter] > max_freq:
                max_freq = segment_freq[letter]
                max_freq_letter = letter
        
        # Assuming this is the letter 'e'
        key_letter = chr((ord(max_freq_letter) - 101) + 97)
        key_guess += key_letter
        
    return key_guess


# Function to crack the Vigenere cipher using Kasiski examination
def vignere_crack_kasiski(ciphertext):
    est_key_len = estimate_key_length(ciphertext)
    print("Estimated Key Length:", est_key_len)
    key_guess = frequency_analysis(ciphertext, est_key_len)
    print("Guessed Key:", key_guess)
    plaintext = vignere_decode(ciphertext, key_guess)
    with open("predicted.txt", "w") as f:
        f.write(plaintext)
    

def main():
    # Part 1: Encode and decode
    plaintext = ""
    key = ""
    
    with open("key.txt", "r") as f:
        key = f.read().strip()
    with open("input.txt", "r") as f:
        for line in f:
            plaintext += line.strip()
    
    
    ciphertext = vignere_encode(plaintext, key)
    back_to_plaintext = vignere_decode(ciphertext, key)
    
    with open("encoded.txt", "w") as f:
        f.write(ciphertext)
        
    # Part 2: Crack Kasiski
    vignere_crack_kasiski(ciphertext)


if __name__ == "__main__":
    main()
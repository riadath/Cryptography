import matplotlib.pyplot as plt
import collections
import math

def vignere_encode(plaintext, key):
    plaintext = list(plaintext)
    key = list(key.lower())  
    
    for i in range(len(key)):
        key[i] = ord(key[i]) - 97
    
    for i in range(len(plaintext)):
        plaintext[i] = ord(plaintext[i])
        
    for i in range(len(plaintext)):
        plaintext[i] = (plaintext[i] + key[i % len(key)]) % 255
        
        if plaintext[i] > 90 and plaintext[i] < 97:
            plaintext[i] = ord('a') + (plaintext[i] - 91)
        if plaintext[i] > 122:
            plaintext[i] = ord('A') + (plaintext[i] - 123)
        
    for i in range(len(plaintext)):
        plaintext[i] = chr(plaintext[i])

    plaintext = "".join(plaintext)
    return plaintext

def vignere_decode(ciphertext, key):
    ciphertext = list(ciphertext)
    key = list(key.lower())  
    
    for i in range(len(key)):
        key[i] = ord(key[i]) - 97
    
    for i in range(len(ciphertext)):
        ciphertext[i] = ord(ciphertext[i])
        
    for i in range(len(ciphertext)):
        ciphertext[i] = (ciphertext[i] - key[i % len(key)]) % 255
        
        if ciphertext[i] < 65:
            ciphertext[i] = ord('z') - (64 - ciphertext[i])
        elif ciphertext[i] > 90 and ciphertext[i] < 97:
            ciphertext[i] = ord('Z') - (96 - ciphertext[i])
        
    for i in range(len(ciphertext)):
        ciphertext[i] = chr(ciphertext[i])

    ciphertext = "".join(ciphertext)
    return ciphertext

def plot_frequency_analysis(segment, letter_no):
    letter_counts = collections.Counter(segment)
    letters, counts = zip(*letter_counts.most_common())
    letters = [chr(i) for i in range(97, 123)]
    counts = [letter_counts[letter] for letter in letters]

    plt.title(f"Letter No: {letter_no} of the key")
    plt.bar(letters, counts)
    plt.show()

def estimate_key_length(ciphertext):
    substrings = {}
    for i in range(len(ciphertext) - 2):
        substring = ciphertext[i : i + 3]
        if substring in substrings:
            substrings[substring].append(i)
        else:
            substrings[substring] = [i]
    
    distances = {}
    for substring in substrings:
        if len(substrings[substring]) > 1:
            for i in range(1, len(substrings[substring])):
                distance = substrings[substring][i] - substrings[substring][i - 1]
                if distance in distances:
                    distances[distance] += 1
                else:
                    distances[distance] = 1

    gcd_distances = math.factorial(50)
    for distance in distances:
        if distances[distance] > 1:
            if math.gcd(gcd_distances, distance) > 3:
                gcd_distances = math.gcd(gcd_distances, distance)
    print("GCD Distances:", gcd_distances)
    
    return gcd_distances

def frequency_analysis(ciphertext, estimated_key_length):
    segments = [""] * estimated_key_length
    for i, char in enumerate(ciphertext):
        segments[i % estimated_key_length] += char
    key_guess = ""
    for segment in segments:
        segment_freq = collections.Counter(segment)
        segment_freq = dict(sorted(segment_freq.items()))
        total_count = sum(segment_freq.values())
        segment_freq = {k: v / total_count * 100 for k, v in segment_freq.items()}
        
        max_freq, max_freq_letter = 0, ''
        for letter in segment_freq:
            if segment_freq[letter] > max_freq:
                max_freq = segment_freq[letter]
                max_freq_letter = letter
        
        key_letter = chr((ord(max_freq_letter) - 101) + 97)
        key_guess += key_letter
        
    return key_guess

def vignere_crack_kasiski(ciphertext):
    est_key_len = estimate_key_length(ciphertext)
    print("Estimated Key Length:", est_key_len)
    key_guess = frequency_analysis(ciphertext, est_key_len)
    print("Guessed Key:", key_guess)
    plaintext = vignere_decode(ciphertext, key_guess)
    with open("predicted.txt", "w") as f:
        f.write(plaintext)

def main():
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
        
    vignere_crack_kasiski(ciphertext)

if __name__ == "__main__":
    main()
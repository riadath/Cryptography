import matplotlib.pyplot as plt
import collections


def vignere_encode(plaintext, key):
    plaintext = list(plaintext)
    key = list(key)
    for i in range(len(plaintext)):
        plaintext[i] = ord(plaintext[i]) - 97
        
    for i in range(len(key)):
        key[i] = ord(key[i]) - 97
        
    for i in range(len(plaintext)):
        plaintext[i] = 97 + (plaintext[i] + key[i % len(key)])%26
        
    for i in range(len(plaintext)):
        plaintext[i] = chr(plaintext[i])
    
        
    plaintext = "".join(plaintext)
    return plaintext

    
def vignere_decode(ciphertext, key):
    ciphertext = list(ciphertext)
    key = list(key)
    for i in range(len(ciphertext)):
        ciphertext[i] = ord(ciphertext[i]) - 97
    for i in range(len(key)):
        key[i] = ord(key[i]) - 97
    for i in range(len(ciphertext)):
        ciphertext[i] = 97 + (ciphertext[i] - key[i % len(key)])%26
        
    for i in range(len(ciphertext)):
        ciphertext[i] = chr(ciphertext[i])
    ciphertext = "".join(ciphertext)
    return ciphertext


def estimate_key_length(ciphertext):
    return [4]  # Placeholder for actual estimation method

def frequency_analysis(ciphertext, estimated_key_length):
    segments = [''] * estimated_key_length
    for i, char in enumerate(ciphertext):
        segments[i % estimated_key_length] += char
    print(segments)
    key_guess = ''
    for segment in segments:
        plot_frequency_analysis(segment)
        segment_freq = collections.Counter(segment)
        most_common_char, _ = segment_freq.most_common(1)[0]

        # key_guess_char = (ord(most_common_char) - ord('e')) % 26
        # key_guess += chr(key_guess_char + 97)

    return key_guess

# plot graph for segment_freq
def plot_frequency_analysis(segment):
    # Frequency analysis for plotting
    letter_counts = collections.Counter(segment)
    letters, counts = zip(*letter_counts.most_common())

    # Plotting
    plt.bar(letters, counts)
    plt.show()

def vignere_crack_kasiski(ciphertext):
    key_guess = frequency_analysis(ciphertext, 4)
    pass


def main():
    
    # part 1, encode and decode
    plaintext = ""
    key = "joke"
    fin = open("input.txt", "r")
    for line in fin:
        plaintext += line.strip()
    fin.close()
    
    ciphertext = vignere_encode(plaintext, key)
    plaintext_decoded = vignere_decode(ciphertext, key)

    
    to_write = ""
    for i in range(0, len(plaintext_decoded), 5):
        to_write += plaintext_decoded[i:i+5] + " "

    fout = open("output.txt", "w")
    fout.write(to_write)
    fout.close()
    
    
    # part 2, crack kasiski
    vignere_crack_kasiski(ciphertext)
    
    
    
if __name__ == '__main__':
    main()
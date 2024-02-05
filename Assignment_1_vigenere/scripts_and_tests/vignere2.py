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
        segment_freq = collections.Counter(segment)
        print(segment_freq)
        most_common_char, _ = segment_freq.most_common(1)[0]
        key_guess_char = (ord(most_common_char) - ord('e')) % 26
        key_guess += chr(key_guess_char + 97)

    return key_guess

def plot_frequency_analysis(segment):
    # Frequency analysis for plotting
    letter_counts = collections.Counter(segment)
    letters, counts = zip(*letter_counts.most_common())

    # Plotting
    plt.figure(figsize=(10, 6))
    plt.bar(letters, counts, color='skyblue')
    plt.title("Frequency Analysis of a Ciphertext Segment")
    plt.xlabel("Letters")
    plt.ylabel("Frequency")
    plt.xticks(rotation=45)
    plt.grid(axis='y', linestyle='--')
    plt.show()

def vignere_crack(ciphertext):
    estimated_key_lengths = estimate_key_length(ciphertext)
    for estimated_key_length in estimated_key_lengths:
        key_guess = frequency_analysis(ciphertext, estimated_key_length)
        print(f"Estimated Key Length: {estimated_key_length}, Key Guess: {key_guess}")
        predicted_message = vignere_decode(ciphertext, key_guess)
        with open("predicted.txt", "w") as fout:
            fout.write(predicted_message)

    # Optionally, plot frequency analysis for the first segment as an example
    first_segment = ciphertext[:estimated_key_lengths[0]]  # Adjust as needed
    # plot_frequency_analysis(first_segment)

def main():
    with open("input.txt", "r") as fin:
        plaintext = fin.read().strip()
    with open("key.txt", "r") as fkey:
        key = fkey.read().strip()
    
    ciphertext = vignere_encode(plaintext, key)
    with open("output.txt", "w") as fout:
        fout.write(ciphertext)
    
    vignere_crack(ciphertext)

if __name__ == '__main__':
    main()

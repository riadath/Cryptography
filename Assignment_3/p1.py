def xor_bytes(bytes1, bytes2):
    return [b1 ^ b2 for b1, b2 in zip(bytes1, bytes2)]

def get_words_file(filename):
    with open(filename, 'r') as f:
        words = f.read().split()
    return words

def find_words_and_key(words, xor_result, encrypted_word):
    for word in words:
        other_word = ''.join(chr(ord(c) ^ b) for c, b in zip(word, xor_result))
        if other_word in words:
            print(f"The words are '{word}' and '{other_word}'")
            word_bytes = [ord(c) for c in word]
            key = xor_bytes(word_bytes, encrypted_word)
            print("The key is:", key)
            return word, other_word, key
    return None, None, None

def main():
    encrypted_words = [
        [0xe9, 0x3a, 0xe9, 0xc5, 0xfc, 0x73, 0x55, 0xd5],
        [0xf4, 0x3a, 0xfe, 0xc7, 0xe1, 0x68, 0x4a, 0xdf],
    ]

    xor_results = [xor_bytes(encrypted_words[i], encrypted_words[i+1]) for i in range(len(encrypted_words)-1)]

    words = get_words_file('Assignment_3/dictionary')
    words = [word for word in words if len(word) == 8]

    for i in range(len(xor_results)):
        word1, word2, key = find_words_and_key(words, xor_results[i], encrypted_words[i])
        if word1 is None:
            print("No matching words found.")

if __name__ == "__main__":
    main()
import string
import itertools
import re


valid_characters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ' ', ',', '.', '!', '?', '-', '(', ')']

def is_valid_character(character):
    return character in valid_characters

def generate_keys(cipher_texts, idx):
    keys = []
    for i in range(256):
        is_valid = True
        for cipher_text in cipher_texts:
            previous_cipher = cipher_text[idx-1] if idx > 0 else 0
            plain_text_char = chr(cipher_text[idx] ^ ((i + previous_cipher) % 256))
            if not is_valid_character(plain_text_char):
                is_valid = False
                break
        if is_valid:
            keys.append(i)
    return keys

def decrypt_text(cipher_text, key, start, end):
    plain_text = ""
    key_idx = 0
    for i in range(start, end):
        previous_cipher = cipher_text[i-1] if i > 0 else 0
        plain_text += chr(cipher_text[i] ^ ((key[key_idx] + previous_cipher) % 256))
        key_idx += 1
    return plain_text

def is_valid_english_word(word, english_words):
    return word.lower() in english_words

def find_word_limits(cipher_texts, all_keys):
    word_limits = []
    for cipher_text in cipher_texts:
        limits_for_this_text = [0]
        for i in range(60):
            is_limit = True
            for key in all_keys[i]:
                previous_cipher = cipher_text[i-1] if i > 0 else 0
                plain_text_char = chr(cipher_text[i] ^ ((key + previous_cipher) % 256))
                if plain_text_char not in ' ,.?!-()':
                    is_limit = False
                    break
            if is_limit:
                limits_for_this_text.append(i)
        limits_for_this_text = list(set(limits_for_this_text))
        word_limits.append(sorted(limits_for_this_text))
    return word_limits

def find_valid_english_words(cipher_texts, all_keys, word_limits, english_words):
    valid_words_all = {}
    valid_words_text = {}
    for i in range(len(word_limits[0]) - 1):
        start, end = word_limits[0][i], word_limits[0][i+1]
        keys_for_this_limit = [all_keys[i] for i in range(start, end)]
        valid_words_segment = []
        for keys in itertools.product(*keys_for_this_limit):
            decrypted_text = str(decrypt_text(cipher_texts[0], keys, start, end))
            words = re.findall(r'\b\w+\b', decrypted_text)
            if all(is_valid_english_word(word, english_words) for word in words):
                valid_words_segment.extend(words)
        valid_words_text[i] = list(set(valid_words_segment))
    valid_words_all[0] = valid_words_text
    return valid_words_all

def generate_messages(valid_words_all):
    all_messages = {}
    for text_idx, valid_words_text in valid_words_all.items():
        valid_words_all_segments = list(valid_words_text.values())
        possible_messages_text = [' '.join(words) for words in itertools.product(*valid_words_all_segments)]
        all_messages[text_idx] = possible_messages_text
    return all_messages

def find_key(cipher_text, plain_text):
    key = []
    previous_cipher = 0
    for c, p in zip(cipher_text, plain_text):
        k = ((c ^ ord(p)) - previous_cipher) % 256
        if k < 0:
            k = (k+256)%256
        key.append(k)
        previous_cipher = c
    return key

def decrypt_new_text(cipher_text, key):
    plain_text = ""
    key_idx = 0
    for i in range(len(cipher_text)):
        previous_cipher = cipher_text[i-1] if i > 0 else 0
        plain_text += chr(cipher_text[i] ^ ((key[key_idx] + previous_cipher) % 256))
        key_idx += 1
    return plain_text

def main():
    with open("Assignment_3/dictionary", "r") as file:
        english_words_set = set(word.strip() for word in file)

    with open("Assignment_3/cipher", "r") as file:
        cipher_texts = [[int(num) for num in line.strip('[]\n').split(", ")] for line in file.readlines()]

    possible_keys = []
    for i in range(60):
        possible_keys.append(generate_keys(cipher_texts, i))

    word_limits = find_word_limits(cipher_texts, possible_keys)

    valid_words = find_valid_english_words(cipher_texts,possible_keys,word_limits, english_words_set)

    all_possible_messages = generate_messages(valid_words)

    one_time_pad = None
    max_length_sum = 0

    for idx, messages in all_possible_messages.items():
        for message in messages:
            key = find_key(cipher_texts[0], message)
            key.append(0)

            length_sum = 0
            for cipher in cipher_texts:
                decrypted = decrypt_new_text(cipher, key)
                decrypted = re.sub('[^a-zA-Z]', ' ', decrypted)
                words = decrypted.split()
                valid_words = [word for word in words if is_valid_english_word(word, english_words_set)]
                if len(valid_words) >= 4:
                    current_longest_word_length = len(max(valid_words, key=len))
                    length_sum += current_longest_word_length

            if length_sum > max_length_sum:
                max_length_sum = length_sum
                one_time_pad = key
    print(f"one_time_pad: {one_time_pad}")
    if one_time_pad is not None:
        for i, cipher in enumerate(cipher_texts):
            decrypted = decrypt_new_text(cipher, one_time_pad)
            print(f"{decrypted}",end=". ")

if __name__ == "__main__":
    main()
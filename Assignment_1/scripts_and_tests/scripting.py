def remove_spaces_conv_lower(string):
    # replace anything that is not a lowercase english character
    string = ''.join(e for e in string if e.islower() or e.isupper())
    return string  


fin = open('large_text.txt', 'r')


plaintext = ""
for line in fin.readlines():
    line = line.strip()
    if len(line) < 10:
        continue
    plaintext += remove_spaces_conv_lower(line[:len(line)-1])
    
fout = open('input.txt', 'w')
fout.write(plaintext)

fin.close()
fout.close()

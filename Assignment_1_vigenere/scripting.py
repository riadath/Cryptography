def remove_spaces_conv_lower(string):
    string = string.replace('\n', '')
    string = string.replace(' ', '')
    return string.lower()    


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

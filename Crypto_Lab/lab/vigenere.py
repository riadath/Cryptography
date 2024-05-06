import re
import csv
import math


def charToInt(c):

    if ord(c) < 91:
        return ord(c)-ord('A')+26
        
    else:
        return ord(c)-ord('a')



def intToChar(x):

    x = x%52
    if x < 26:   
        return chr(x+ord('a'))
    else:
       return chr(x+ord('A')-26)



def vigenereEncryption(text,key):
   
    keyLength = len(key)
    encryptedText = ""

    for i, c in enumerate(text):
        encryptedInt = charToInt(c) + charToInt(key[i%keyLength])
        encryptedCharachter = intToChar(encryptedInt)
        encryptedText+=encryptedCharachter
    return encryptedText



def formatText(text):

    finalText = ""
    for i,c in enumerate(text):    
        if i%5 == 0 and i != 0:
            finalText+=" "
        finalText+=c
    return finalText



def vigenereDecryption(text,key):

    plainText = text.replace(" ", "")
    keyLength = len(key)
    decryptedText = ""

    for i, c in enumerate(plainText):
        decryptedInt = charToInt(c) - charToInt(key[i%keyLength])
        decryptedCharachter = intToChar(decryptedInt)
        decryptedText+=decryptedCharachter
    return decryptedText



def findKeyLength(text):

    textLength = len(text)
    countArr = []

    #  get the count of matching pairs for every right shift from 1 to 100
    for i in range(1,int(textLength/2)):
        count = 0
        for j in range(textLength-i-1):
            if text[j] == text[j+i]:
                count+=1
        countArr.append(count)
        print(count)
    
    # from the count of matching pairs find the difference between two peek to get the length 
    predictedLength = 0
    predictedLengthArray = []
    startCountingLength = False
    for i in range(len(countArr)-1):
        if startCountingLength == True:
            if countArr[i+1]/countArr[i]<2:
                predictedLength+=1
            else:
                predictedLengthArray.append(predictedLength+1)
                startCountingLength = False
                predictedLength= 0
        else:
           if countArr[i+1]/countArr[i]>=2:
                startCountingLength = True
    if len(predictedLengthArray) == 0:
        return 1
    return max(set(predictedLengthArray), key=predictedLengthArray.count)



def getFreq(text):
    textLength = len(text)
    frequency = []
    for i in range(26):
        frequency.append(round(100*text.count(chr(i+ord("a")))/textLength,10))
    for i in range(26):
        frequency.append(round(100*text.count(chr(i+ord("A")))/textLength,10))
    return frequency



def getAlphabetFrequency():
    with open('alphabetFrequency.csv', mode='r') as infile:
        reader = csv.reader(infile)
        mydict = {rows[0]:rows[1] for rows in reader}
    
    alphabetFreq = []
    for i in range(26):
        alphabetFreq.append(float(mydict.get(chr(i+ord("a")))))
    for i in range(26):
        alphabetFreq.append(float(mydict.get(chr(i+ord("A")))))

    return alphabetFreq



def findpredictedKey(keyLength,text):

    freq = getAlphabetFrequency()
    textLength = len(text)
    nthCharArr = []

    for i in range(keyLength):
        tempCharArr = ""
        for j in range(i,textLength,keyLength):
            tempCharArr+=text[j]
        nthCharArr.append(tempCharArr)
    
    finalPredictedKey = ""

    for i in range(keyLength):
        cipherTextFreq = getFreq(nthCharArr[i])
        isCipherCharachterFound = False
        for j in range(52):
            for k in range(25):
                if freq[k] > cipherTextFreq[(k+j)%52]+5 or freq[k] < cipherTextFreq[(k+j)%52]-5:
                    break
                else:
                    if k == 24:
                        isCipherCharachterFound = True
            if isCipherCharachterFound == True:
                if j<26:
                    finalPredictedKey+=chr(ord('a')+j)
                else:
                    finalPredictedKey+=chr(ord('A')+j-26)
                break
        if isCipherCharachterFound == False:
            finalPredictedKey+="X"

    return finalPredictedKey

def kasiskiKeyLength(cipherText):
    frequency = {}
    size = len(cipherText)
    for i in range(size - 3):
        segment = cipherText[i:i+3]
        if segment not in frequency.keys():
            frequency[segment] = 0
        frequency[segment] += 1

    #find most occurring 3-letter pattern
    patterns = {}

    for i in range(len(cipherText) - 3):
        pattern = cipherText[i:i+3]
        if pattern not in patterns.keys():
            patterns[pattern] = 0
        patterns[pattern] += 1
    sortedPatterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)
            
    #find probable key length
    occurrences = []
    pattern = sortedPatterns[0][0]

    for i in range(len(cipherText) - 3):
        if cipherText[i:i+3] == pattern:
            occurrences.append(i)
            
    probableLengths = []
    for i in range(1, len(occurrences)):
        probableLengths.append(occurrences[i] - occurrences[i-1])
        
    probableLength = probableLengths[0]
    for i in range(1, len(probableLengths)):
        probableLength = math.gcd(probableLength, probableLengths[i])
    return probableLength
    



    
        
    

    
# get data from input text file
with open('input.txt', 'r') as file:
    inputData = file.read().rstrip()

# make the text into plaintext(pnly A-Z and a-z)
plainText = re.sub('[\W\d_]+', '',  inputData)

# get key data
with open('key.txt', 'r') as file:
    keyData = file.read().rstrip()

# encryption function
encryptedText = vigenereEncryption(plainText,keyData)

#format text to five leter words
formattedText = formatText(encryptedText)

#save text to output.txt
with open("Output.txt", "w") as text_file:
    text_file.write("Formatted Text:\n\n")
    text_file.write(formattedText)
with open("encryptedOutput.txt", "w") as text_file:
    text_file.write(formattedText)

# decrypt function
with open('encryptedOutput.txt', 'r') as file:
    inputData = file.read().rstrip()
formattedText = inputData
decryptedText = vigenereDecryption(formattedText,keyData)

# save decrypted text to output.txt
with open("Output.txt", "a") as text_file:
    text_file.write("\n\n\nDecrypted Text:\n\n")
    text_file.write(decryptedText)



# finding key length function
encryptedText = formattedText.replace(" ", "")
print("predicted key length:" + str(kasiskiKeyLength(encryptedText)))
predictedKeyLength = findKeyLength(encryptedText)

# predict key function
predictedKey = findpredictedKey(predictedKeyLength,encryptedText)
print("Predicted Key: " + predictedKey)

#decipher the encrypted text using predicted key into a textfile
predictedDecryptedText = vigenereDecryption(formattedText,predictedKey)
with open("PredictedOutput.txt", "w") as text_file:
    text_file.write("Predicted Text:\n\n")
    text_file.write(predictedDecryptedText)







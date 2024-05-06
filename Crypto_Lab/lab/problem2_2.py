from BitVector import *
import itertools



validCharachters = [" ",",",".","!","?","(",")","-",'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
validAlphaneumerics = [" ",",",".","!","?","(",")","-"]


def getAllPossibleWords(length,isFirst):

    wordList = []

    with open("words.txt") as file:
        
        for line in file:
            
            if len(line) == length+1:
                
                line = line[:-1]
                if "'" in line:
                    
                    continue
                if isFirst:
                    
                    wordList.append(line.capitalize())
                else:
                    
                    wordList.append(line.lower())
   
    return wordList




def find_highest_value(lst, key):
    
    highest_value = float('-inf')
    
    for i in lst:
        
        if i <= key and i > highest_value:
            
            highest_value = i
            
    if highest_value == float('-inf'):
        
        return None
    
    return highest_value


def find_lowest_value(lst, key):
    
    lowest_value = float('inf')
    
    for i in lst:
        
        if i > key and i < lowest_value:
            
            lowest_value = i
            
    if lowest_value == float('inf'):
        
        return 59
    
    return lowest_value





def all_combinations(lists,startingIndex,length):
    
    finalLists = []
    
    for x in range(startingIndex,startingIndex+length):
        
        finalLists.append(lists[x])
    
    result = []
    
    for item in itertools.product(*finalLists):
        
        result.append(list(item))
        
    return result


def getArrayOfCipherTextsFromFile():

    encryptWords = []
    
    with open ("input2.txt", "r") as myfile:
        encryptWords = myfile.read().splitlines()
        
    arrayOfNums = []
    
    for x in encryptWords:
        
        x = x.strip("[]")
        x = x.split(",")
        x = list(map(int, x))
        arrayOfNums.append(x)
        
    return arrayOfNums




def getAllPossibleKeys(arrayOfCiphers):
    
    # list of the indexes for the values for [" ",",",".","!","?","(",")","-"] in every cipherText
    listOfValidWordBreaker = list_of_lists = [[] for i in range(10)]

    #list of all possible keys for every index
    templistOfList = []
    
    # loop for every index for a particular ciphertext. here 0-60
    for x in range(0,len(arrayOfCiphers[0])):

        listofValidKeys = []
        tempstr = ""
        
        # loop for all possible key combination
        for y in range(0,2<<7):
            
            isKey = True
            # loop for each ciphertext of the 10 ciphertexts
            for  z in arrayOfCiphers:

                # condition for previous cipher
                if x>0:
                    
                    tempInt = (z[x-1]+y)%256
                    
                else:
                    
                    tempInt = int(y)

                # decypher mechanism
                tempbv = BitVector(intVal = tempInt,size = 8)
                bv1 = BitVector(intVal = z[x],size = 8)
                xorbv = bv1^tempbv
                charValue = xorbv.get_text_from_bitvector()
                tempstr+=charValue

                # check if it is valid charachter
                if  (charValue in validCharachters):
                    
                    continue
                
                else:
                    
                    isKey = False
                    break
            # add the key if the result charchter is valid for every combination  
            if isKey == True:
                
                listofValidKeys.append(y)
                
                # add the [" ",",",".","!","?","(",")","-"] index to the list for every cipher texts
                for i,w in enumerate(tempstr):
                    
                    if w in validAlphaneumerics:
                        
                        listOfValidWordBreaker[i].append(x)
      
           
            tempstr=""
            
        templistOfList.append(listofValidKeys)
        
    return templistOfList,listOfValidWordBreaker




def decryptFunction(cipherText,key,length,iniIndex,isFirst):
    
    if isFirst:
        
        previousCipherBV = BitVector(intVal = 0,size = 8)
    else:
        
        previousCipherBV = BitVector(intVal = cipherText[iniIndex-1],size = 8)
  
    ans = BitVector(size = 0)

    for x in range(iniIndex,length+iniIndex):  

        temp = int(previousCipherBV)+key[x-iniIndex]
        temp = temp%256
        ans+=BitVector(intVal = temp,size = 8)^BitVector(intVal = cipherText[x],size = 8)
        previousCipherBV = BitVector(intVal = cipherText[x],size = 8)
        
    return ans.get_text_from_bitvector()




def getValidWordBreakerlist(lists):
    
    temp = []
    
    for x in lists:
        
        temp.append(sorted(list(set(x))))
        
    return temp



def getTheRightKeyCombination(validWordBreakerlist,listOfListofPossibleKeys,arrayOfCiphers):
    
    print("getting the right key. This will take some time....")
    
    isFirstWord = True
    indexOfArrayOfCiphers = 0
    initialIndex = 0
    finalKey = []
    x = 0
    count = 0
    
    while(True):
        
        count+=1
        
        highestLength = 0

        if isFirstWord:
            for index,y in enumerate(validWordBreakerlist):
                if y[0]>highestLength:
                    highestLength = y[0]
                    indexOfArrayOfCiphers = index
            highestLength+=1
            initialIndex = 0

        else:
            for index,y in enumerate(validWordBreakerlist):
            
                if x+1 in y: continue
                if x in y: continue
                diff = find_lowest_value(y,x) - find_highest_value(y,x)
        
                if index!=indexOfArrayOfCiphers and diff>highestLength :
                    
                    highestLength = diff
                    indexOfArrayOfCiphers = index
                    initialIndex = find_highest_value(y,x)
                    
            initialIndex+=1

        
 
        allWords = getAllPossibleWords(highestLength-1,isFirstWord)
        allPossibleKeyCombination=all_combinations(listOfListofPossibleKeys,initialIndex,highestLength-1)


        tempInd = 0  
        
        # this part is unnecessary. Here it is used for making the programme faster. as we know the answer. remove this part if you want to try different cipher texts
        # if count == 1:
        #     tempInd = 47000
        # elif count==4:
        #     tempInd = 5000
    
              
         
        possibleWords = 0
        tempKeyCombination = []
        
        for y in range(tempInd,len(allPossibleKeyCombination)):

            temp = decryptFunction(arrayOfCiphers[indexOfArrayOfCiphers],allPossibleKeyCombination[y],highestLength-1,initialIndex,isFirstWord)
    
            if temp in allWords:
                
                possibleWords +=1
                tempKeyCombination.append(allPossibleKeyCombination[y])

        if len(finalKey) == 0:
            
            finalKey = tempKeyCombination[0]
        else:
            
            length = len(finalKey)
            
            for x in range(0,len(tempKeyCombination[0])):
                
                if initialIndex+x>=length:
                    
                    finalKey.append(tempKeyCombination[0][x])

        # if possibleWords != 1:

        if initialIndex+highestLength >=60: break
        
        x = initialIndex+highestLength-1
        
        isFirstWord = False
        
        for i in cipherArray:
            
            print(decryptFunction(i,finalKey,initialIndex+highestLength-1,0,True))
        print("\n")
        



    for x in range(len(finalKey),len(listOfListofPossibleKeys)):
        
        finalKey.append(listOfListofPossibleKeys[x][0])
        
    for i in cipherArray:
        
            print(decryptFunction(i,finalKey,60,0,True))
            
    return finalKey

    



# function to get all cipherText from textFile
cipherArray = getArrayOfCipherTextsFromFile()
# function to get the list of all possible keys for every index
listOfPossibleKeyslist,listOfValidWordBreaker = getAllPossibleKeys(cipherArray)
# function to get all the valid word termination indexes for every ciphertext
listOfValidWordBreaker = getValidWordBreakerlist(listOfValidWordBreaker)
#function to get the key
finalAns = getTheRightKeyCombination(listOfValidWordBreaker,listOfPossibleKeyslist,cipherArray)

with open("output2.txt", "w") as a_file:
    a_file.write(str(finalAns))



       


#==================================================
# This program does the following:
#   - ENCRYPTS: given plaintext and a key it encrypts the plaintext as a 
#   Vigenere Cipher using the key
#       - cmd line args: -e <plaintext> <key>
#
#   - DECRYPTS: given ciphertext (encyrpted using a Vigenere Cipher) and 
#   a key it will decrypt the ciphertext and return the decrypted plaintext
#       - cmd line args: -d <ciphertext> <key>
#
#   - BREAKS: given just ciphertext it breaks the Vigenere Cipher and returns 
#   the plaintext
#       - cmd line args: -b <ciphertext>
#       - NOTE: In order for the ciphertext to be broken it MUST be long enough
#       to match relative letter frequencies of actual english text
#       - FOR EXAMPLE THE FOLLOWING CIPHERTEXT CAN BE BROKEN IN BREAK MODE:
#
#       ZRSJWYHZRLJMTUFYFFBUHIIDKDRGRLGDJVWESLCVNVKCVKZGBNILJWYHWMDNMQZZXZVPRH
#       EHKQNJRIQKCVQDESGBGFPVPDPWEBVXSFZLERVWUIAGPLGNMJLKLFQBULEKAPQGWFWAVLBZ
#       ESFQZGRVELKBJDJEZQJOLKLGNMNQUXZCBZHRRKEWZIFVLKBUDUEHGZSHTXDAZBXEHVQWEO
#       ZOWCXBUKLGNMCDZRLGLTUVIFYQGKRWZKVLBVPDQEOURWKMVBEZRLJMRARGLOQQGCILJMQR
#       FVGRMAHUSFVWNWLFWUPNSVHZCTYOZOWCBHQEIDCDRUPGGONBUKETNMGXERWNEVWYSMVAZR
#       BIOKBUSRRWNTRGNEDNANQUJDQWEVKMDGLNQUGSTXRWVHHTWILUIVYQGKGSDKAUHUGZCQEV
#       RRVNWGVRRVNWGVFJHGOFIFVZCBFDEHUQIGVKLWJWOEZXOCASREHGHDVVZXGTAGKVXMPVRO
#       NSMPLBQRRVQVTRZRYHIVUCCTWBARKUMKBRVKVSKOUWZRLQBUHJMVGWSWYIZKTYWYIZKTYD
#       JEDNBUHGIGRTRIFVECVLPZPWUZBXEHUCTYHUMLCVQPRRQNQGWCIJQCAGUSGTABSVRWFWHW
#       FJAVNVUJXGPWAHJMVGIAGKLWPWADESLJMEQFKGKVTXGWLCQEVWSJVPRKFFTKBOHUVGQUFE
#       RXZTWBPJGWNTNUJTSPBELVWDQBFRWXZGARZRVVTWOHJLWJIQZYSDGZBRDWVGDBWVHLQKYR
#       KLWUSVWTLWPAQLEMFIZBRDWSNTJHIIGPBUHJEEGNYRFVSPLVQUIWFWAWYIKCURSRWKCORW
#       YITGAGUFSEUERUVEDNWAWYIDGNGKRRVUQQHXSAPOVQWSJVPRVVAWTMGKVSFNGBQVWLQPNY
#       VAAPLBZJHWGXFHKVGWVQZZRVQEFOFSCKVTRMIJJQFJRVVGVNQUQWCLBZJFWAWAGJPGRQAJ
#       USOPBBWYIJKDRUKLAUPBESMLYIFDMIJAEROCXGFWURSFAVIAGYMKPIZHNEKDITJZRKVPRE
#       RKYKVFHJLSFTVYVHAPBUHEIAIPORLVZQWQRWXZGPVOCJGTBVPVSMVWSPZRVCVQSVSHNMPR
#       EWAFMEHUXZGUIHICJGACHTXSDTRQFXGPTLEVGSWARPFWLQNGKVQOGZRUZGZDCGDCWGDMPD
#       LWWVPRBEINGZUDUEFAIQYVRLWZRVFVVKLNQPXZKVTXEIPRMPWVHQQCPRLPVVMYONLSVIOD
#
#   NOTE: PLAINTEXT AND CIPHERTEXT CANNOT CONTAIN SPACES OR ANY SPECIAL CHARACTERS
#   ONLY LETTERS
#
# Written and Property of Michael Ficaro
#==================================================
import sys
from collections import deque
from operator import itemgetter

# Converts a character to its corresponding index
charToNum = {"A": 0, "B": 1, "C": 2, "D": 3, "E": 4, "F": 5,
    "G": 6, "H": 7, "I": 8, "J": 9, "K": 10, "L": 11,
    "M": 12, "N": 13, "O": 14, "P": 15, "Q": 16, "R": 17,
    "S": 18, "T": 19, "U": 20, "V": 21, "W": 22, "X": 23,
    "Y": 24, "Z": 25}

# Converts an index to its corresponding letter
numToChar = {0:"A", 1:"B", 2:"C", 3:"D", 4:"E", 5:"F",
    6:"G", 7:"H", 8:"I", 9:"J", 10:"K", 11:"L",
    12:"M", 13:"N", 14:"O", 15:"P", 16:"Q", 17:"R",
    18:"S", 19:"T", 20:"U", 21:"V", 22:"W", 23:"X",
    24:"Y", 25:"Z"}

# Dictionary of the true relative frequency of letters in English Text
relLetterFreq = { "A": .08167, "B": .01492, "C": .02782, "D": .04253, "E": .12702, "F": .02228,
    "G": .02015, "H": .06094, "I": .06996, "J": .00153, "K": .00772, "L": .04025,
    "M": .02406, "N": .06749, "O": .07507, "P": .01929, "Q": .00095, "R": .05987,
    "S": .06327, "T": .09056, "U": .02758, "V": .00978, "W": .02360, "X": .00150,
    "Y": .01974, "Z": .00074 }

# Creates a Vigenere Cipher from a string of plaintext
def EncryptVigenereCipher(key, text):
    result = ""
    for index in range(len(text)):
        result += numToChar[
            (charToNum[text[index].capitalize()] + 
             charToNum[key[index % len(key)].capitalize()]) % 26]

    return result

# Decrypts a Vigenere Cipher from a string of ciphertext
def DecryptVigenereCipher(key, text):
    result = ""
    for index in range(len(text)):
        result += numToChar[
            (charToNum[text[index].capitalize()] - 
             charToNum[key[index % len(key)].capitalize()]) % 26]

    return result

# Calculates population vaiance from dictionary with relative frequency as keys
def CalculatePopulationVariance(dic):
    N = len(dic)

    mean = 0
    for value in dic.values():
        mean += value
    mean /= (N * 1.0)

    popVar = 0
    for value in dic.values():
        popVar += ((value - mean) ** 2)

    popVar /= N

    return popVar

def GetVarianceFromText(text):
    dic = { "A": 0, "B": 0, "C": 0, "D": 0, "E": 0, "F": 0,
    "G": 0, "H": 0, "I" : 0, "J": 0, "K": 0, "L": 0,
    "M": 0, "N": 0, "O": 0, "P": 0, "Q": 0, "R": 0,
    "S": 0, "T": 0, "U": 0, "V": 0, "W": 0, "X": 0,
    "Y": 0, "Z": 0 }

    for letter in text:
        if letter.capitalize() not in dic:
            continue
        dic[letter.capitalize()] += 1

    # get the size
    size = 0
    for value in dic.values():
        size += value

    # get the frequency
    for key in dic.keys():
        dic[key] /= (size * 1.0)

    return CalculatePopulationVariance(dic)
    
# Given Caesar Cipher text this finds the offset as a char
def BreakCaesarCipher(cipher):
    dic = { "A": 0, "B": 0, "C": 0, "D": 0, "E": 0, "F": 0,
    "G": 0, "H": 0, "I" : 0, "J": 0, "K": 0, "L": 0,
    "M": 0, "N": 0, "O": 0, "P": 0, "Q": 0, "R": 0,
    "S": 0, "T": 0, "U": 0, "V": 0, "W": 0, "X": 0,
    "Y": 0, "Z": 0 }

    for letter in cipher:
        if letter.capitalize() not in dic:
            continue
        dic[letter.capitalize()] += 1

    size = 0
    for value in dic.values():
        size += value

    for key in dic.keys():
        dic[key] /= (size * 1.0)
        dic[key] = round(dic[key], 5)

    # use chi squared test to get offset
    refList = sorted([ [k,v] for k,v in relLetterFreq.items() ], key=itemgetter(0))
    dicList = sorted([ [k,v] for k, v in dic.items() ], key=itemgetter(0))
    dicDeque = deque(dicList)

    offsetChiSquared = []
    for i in range(len(refList)): # rotation
        sum = 0
        for j in range(len(refList)): # letter comparison
            sum += (((dicDeque[j][1] - refList[j][1]) ** 2)/refList[j][1])
        offsetChiSquared.append(sum)
        dicDeque.rotate(-1)

    return numToChar[offsetChiSquared.index(min(offsetChiSquared))]

# Given a Vignenere cipher this finds the key
def BreakVigenereCipher(cipherText):
    benchmark = round(CalculatePopulationVariance(relLetterFreq), 3)
    popVar = 0
    counter = 1
    resultList = []
    while True:
        if counter > len(cipherText):
            print "ERROR: CipherText not large enough to break"
            return
        cipherList = [""]*counter
        for index in range(len(cipherText)):
            cipherList[index % counter] += cipherText[index]

        avgPopVar = 0
        for cipher in cipherList:
            avgPopVar += GetVarianceFromText(cipher)
        avgPopVar /= counter

        popVar = avgPopVar
        if round(popVar, 3) == benchmark:
            resultList = cipherList
            break
        counter += 1

    key = ""
    for cipherBlock in resultList:
        key += BreakCaesarCipher(cipherBlock)

    print "KEY: " + key
    
    result = ""
    for index in range(len(cipherText)):
        result += numToChar[
            (charToNum[cipherText[index].capitalize()] - 
            charToNum[key[index % len(key)].capitalize()]) % 26]

    print "PLAINTEXT: " + result

# print error message
def PrintArgError():
    print "ERROR: INVALID ARGS"
    print "Encrypt mode: '-e <plaintext> <key>'"
    print "Decrypt mode: '-d <ciphertext> <key>'"
    print "Break mode: '-b <ciphertext>'"

# Main function
def main():
    if len(sys.argv) < 2 or len(sys.argv) > 4:
        PrintArgError()
        return
        
    if sys.argv[1] == "-e": 
        # encypt mode
        if len(sys.argv) != 4:
            PrintArgError()
            return

        print EncryptVigenereCipher(sys.argv[3], sys.argv[2])
    elif sys.argv[1] == "-d":
        # decrypt mode
        if len(sys.argv) != 4:
            PrintArgError()
            return

        print DecryptVigenereCipher(sys.argv[3], sys.argv[2])
    elif sys.argv[1] == "-b":
        # break mode
        if len(sys.argv) != 3:
            PrintArgError()
            return

        BreakVigenereCipher(sys.argv[2])
    else:
        PrintArgError()
        return
    return


if __name__ == "__main__":
    main()
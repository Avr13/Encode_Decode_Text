from codes import *

class emoji_code:
    def encrypt(self, message):
        cipher = ''
        for letter in message:
            if letter != '😁':
                if letter not in EMOJI_CODE_DICT:
                    cipher += letter 
                else:
                    cipher += EMOJI_CODE_DICT[letter] + '😁'
            else:
                cipher += '😁'

        return cipher

    def decrypt(self, encoded_message):
        encoded_message += ' '
        decipher = ''
        citext = ''
        for letter in encoded_message:
            if (letter != '😁'):
                i = 0
                citext += letter
            else:
                i += 1
                if i == 2 :
                    decipher += ' '
                else:
                    decipher += list(EMOJI_CODE_DICT.keys())[list(EMOJI_CODE_DICT.values()).index(citext)]
                    citext = ''

        return decipher

class morse_code:
    def encrypt(self, message):
        cipher = ''
        for letter in message:
            if letter != ' ':
                if letter not in MORSE_CODE_DICT:
                    cipher += letter 
                else:
                    cipher += MORSE_CODE_DICT[letter] + ' '
            else:
                cipher += ' '
    
        return cipher

    def decrypt(self, encoded_message):
        encoded_message += ' '
        decipher = ''
        citext = ''
        for letter in encoded_message:
            if (letter != ' '):
                i = 0
                citext += letter
            else:
                i += 1
                if i == 2 :
                    decipher += ' '
                else:
                    decipher += list(MORSE_CODE_DICT.keys())[list(MORSE_CODE_DICT
                    .values()).index(citext)]
                    citext = ''
    
        return decipher
    
class number_code:
    pass

class hash_code:
    pass
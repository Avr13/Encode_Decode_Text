from codes import *
from cryptography.fernet import Fernet

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

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

class fernet_code:
    def encrypt(self, message:str):
        key = Fernet.generate_key()
        fernet = Fernet(key)
        encMessage = fernet.encrypt(message.encode())
        return {"text": message, "encrypt": encMessage, "decode_key": fernet}
    
    def decrypt(self, encoded_message, decode_key):
        decMessage = decode_key.decrypt(encoded_message).decode()
        return {"text": encoded_message, "decrypt": decMessage}

class password_code:
    # Function to generate a key from a password
    def __derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    # Function to encrypt a message
    def encrypt(self, message: str, password: str) -> str:
        salt = os.urandom(16)
        key = self.__derive_key(password, salt)
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        encrypted_message = salt + iv + ciphertext + encryptor.tag
        return urlsafe_b64encode(encrypted_message).decode()

    # Function to decrypt a message
    def decrypt(self, encrypted_message: str, password: str) -> str:
        encrypted_message = urlsafe_b64decode(encrypted_message)
        
        salt = encrypted_message[:16]
        iv = encrypted_message[16:28]
        ciphertext = encrypted_message[28:-16]
        tag = encrypted_message[-16:]
        
        key = self.__derive_key(password, salt)
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data.decode()

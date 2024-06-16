from generators import *

#Emoji Code
message = "Hello World"
encrypt = emoji_code().encrypt(message=message)
decrypt = emoji_code().decrypt(encoded_message=encrypt)
print(f"Message:{message}\nEncrypt:{encrypt}\nDecrypt:{decrypt}")

#Morse Code
message = "Hello World"
encrypt = morse_code().encrypt(message=message)
decrypt = morse_code().decrypt(encoded_message=encrypt)
print(f"Message:{message}\nEncrypt:{encrypt}\nDecrypt:{decrypt}")
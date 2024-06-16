from fastapi import FastAPI
from generators import emoji_code, morse_code, fernet_code, password_code

app = FastAPI(
    title="APIs",
    description="These are APIs for Encode_Decode backend",
    docs_url="/",
    version="0.1.0",
)

@app.get("/emoji/encrypt")
def emoji_encrypt(message:str):
    encrypt = emoji_code().encrypt(message=message)
    return {"text": message, "encrypt": encrypt}

@app.get("/emoji/decrypt")
def emoji_decrypt(encoded_message:str):
    decrypt = emoji_code().decrypt(encoded_message=encoded_message)
    return {"text": encoded_message, "decrypt": decrypt}

@app.get("/morse/encrypt")
def morse_encrypt(message:str):
    encrypt = morse_code().encrypt(message=message)
    return {"text": message, "encrypt": encrypt}

@app.get("/morse/decrypt")
def morse_decrypt(encoded_message:str):
    decrypt = morse_code().decrypt(encoded_message=encoded_message)
    return {"text": encoded_message, "decrypt": decrypt}

@app.get("/fernet/encrypt")
def fernet_encrypt(message:str):
    encrypt = fernet_code().encrypt(message=message)
    return {"text": message, "encrypt": encrypt}

@app.get("/fernet/decrypt")
def fernet_decrypt(encoded_message:str, decode_key):
    decrypt = fernet_code().decrypt(encoded_message=encoded_message, decode_key=decode_key)
    return {"text": encoded_message, "decrypt": decrypt}

@app.get("/password/encrypt")
def password_encrypt(message:str, password:str):
    encrypt = password_code().encrypt(message=message,password=password)
    return {"text": message, "encrypt": encrypt}

@app.get("/password/decrypt")
def password_decrypt(encoded_message:str,password:str) :
    decrypt = password_code().decrypt(encrypted_message=encoded_message, password=password)
    return {"text": encoded_message, "decrypt": decrypt}

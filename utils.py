import sys
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA


def pad_to_16_bytes(data):
    if len(data) % 16 == 0:
        return data
    padding_length = 16 - (len(data) % 16)
    padding = bytes([0]) * padding_length
    return data + padding


def encryptAES(pin, message: str):
    if len(message) == 0:
        raise ValueError("You must provide the key")

    pin_bytes = pin.encode('utf-8')
    message_bytes = message.encode('utf-8')
    message_bytes = pad_to_16_bytes(message_bytes)

    obj = AES.new(pin_bytes, AES.MODE_CBC, iv=b'1234123412341234')
    ciphertext = obj.encrypt(message_bytes)
    # print(ciphertext.hex())
    return ciphertext.hex()


def decryptAES(pin, ciphertext):
    if len(pin) % 16 != 0:
        raise ValueError("PIN must be a multiple of 16 bytes.")
    
    cipherbytes = bytes.fromhex(ciphertext)
    
    pin_bytes = pin.encode('utf-8')

    obj = AES.new(pin_bytes, AES.MODE_CBC, iv=b'1234123412341234')
    message = obj.decrypt(cipherbytes)
    # print(message)
    message = message.rstrip(b'\x00')  # trim 0 bytes
    return message.decode("utf-8")


def generateRSA():
    key = RSA.generate(4096)
    public_key = key.publickey().export_key()
    private_key = key.export_key()
    return private_key.decode(), public_key.decode()

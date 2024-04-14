import sys
from Crypto.Cipher import AES


def pad_to_16_bytes(data):
    if len(data) % 16 == 0:
        return data
    padding_length = 16 - (len(data) % 16)
    padding = bytes([0]) * padding_length
    return data + padding


def encryptAES(pin, message):
    if len(pin) % 16 != 0:
        raise ValueError("Input data length must be a multiple of 16 bytes.")
    pin_bytes = pin.encode('utf-8')
    message_bytes = message.encode('utf-8')
    message_bytes = pad_to_16_bytes(message_bytes)

    obj = AES.new(pin_bytes, AES.MODE_CBC, iv=b'1234123412341234')
    ciphertext = obj.encrypt(message_bytes)
    print(ciphertext.hex())
    return ciphertext


def decryptAES(pin, cipherbytes):
    if len(pin) % 16 != 0:
        raise ValueError("Input data length must be a multiple of 16 bytes.")
    pin_bytes = pin.encode('utf-8')

    obj = AES.new(pin_bytes, AES.MODE_CBC, iv=b'1234123412341234')
    message = obj.decrypt(cipherbytes)
    print(message)
    message = message.rstrip(b'\x00') # trim 0 bytes 
    return message.decode("utf-8")

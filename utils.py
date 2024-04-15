import sys
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import hashlib
from Crypto.PublicKey.RSA import RsaKey

IV = b'1234123412341234'


def pad_to_16_bytes(data):
    if len(data) % 16 == 0:
        return data
    padding_length = 16 - (len(data) % 16)
    padding = bytes([0]) * padding_length
    return data + padding


def encryptAES(pin, message: str):
    if len(message) == 0:
        raise ValueError("You must provide the key")

    hashed_pin_bytes = hashPin(pin)
    message_bytes = message.encode('utf-8')
    message_bytes = pad_to_16_bytes(message_bytes)

    obj = AES.new(hashed_pin_bytes, AES.MODE_CBC, iv=IV)
    ciphertext = obj.encrypt(message_bytes)
    return ciphertext.hex()


def decryptAES(pin, ciphertext):
    cipherbytes = bytes.fromhex(ciphertext)
    hashed_pin_bytes = hashPin(pin)

    obj = AES.new(hashed_pin_bytes, AES.MODE_CBC, iv=IV)
    message = obj.decrypt(cipherbytes)
    message = message.rstrip(b'\x00')  # trim 0 bytes
    return message.decode("utf-8")


def generateRSA():
    key = RSA.generate(4096)
    public_key = key.publickey().export_key()
    private_key = key.export_key()
    return private_key.decode(), public_key.decode()


def hashPin(pin):
    pin_bytes = pin.encode('utf-8')
    hash_object = hashlib.sha256(pin_bytes)
    hash_hex = hash_object.digest()
    return hash_hex


def is_rsa_public_key(file_contents):
    try:
        # Attempt to parse the file contents as an RSA key
        rsa_key = RSA.import_key(file_contents)
        # Check if the parsed key is a public key
        if isinstance(rsa_key, RsaKey) and rsa_key.has_private():
            return False  # It's a private key, not a public key
        else:
            return True  # It's a public key
    except (ValueError, IndexError, TypeError):
        # RSA key parsing failed
        return False


def is_rsa_private_key(file_contents):
    try:
        # Attempt to parse the file contents as an RSA key
        rsa_key = RSA.import_key(file_contents)
        # Check if the parsed key has a private component
        if isinstance(rsa_key, RsaKey) and rsa_key.has_private():
            return True  # It's a private key
        else:
            return False  # It's not a private key
    except (ValueError, IndexError, TypeError):
        # RSA key parsing failed
        return False

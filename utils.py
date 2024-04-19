import datetime
import os
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.PublicKey import RSA
import hashlib
from Crypto.PublicKey.RSA import RsaKey
import xml.etree.ElementTree as ET


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


def createSignature(file_path, private_key):
    file_size = os.path.getsize(file_path)
    file_extension = os.path.splitext(file_path)[-1]
    file_modified_date = str(
        datetime.datetime.fromtimestamp(os.path.getmtime(file_path)))
    signature_timestamp = str(datetime.datetime.now())

    username = os.getenv('USERNAME')  # For Windows

    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).digest()
        rsa_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_file_hash = cipher_rsa.encrypt(file_hash).hex()

    root = ET.Element("XAdESSignature")
    file_info = ET.SubElement(root, "FileInfo")
    user_info = ET.SubElement(root, "UserInfo")
    ET.SubElement(file_info, "FileSize").text = str(file_size)
    ET.SubElement(file_info, "FileExtension").text = file_extension
    ET.SubElement(file_info, "FileModifiedDate").text = file_modified_date
    ET.SubElement(user_info, "Username").text = username
    ET.SubElement(root, "SignatureTimestamp").text = signature_timestamp
    ET.SubElement(root, "FileHash").text = encrypted_file_hash
    tree = ET.ElementTree(root)
    return tree

    
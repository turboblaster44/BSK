import os
from PyQt6.QtWidgets import QWidget, QPushButton, QHBoxLayout, QFileDialog, QVBoxLayout, QTextEdit, QLineEdit, QInputDialog, QLabel
from PyQt6.QtCore import QStandardPaths
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from utils import create_signature, decryptAES, is_rsa_private_key, is_rsa_public_key, verify_signature


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.window_width, self.window_height = 600, 200
        self.setMinimumSize(self.window_width, self.window_height)
        self.initUI()
        self.public_key = None
        self.private_key = None

    def initUI(self):
        layout = QVBoxLayout()

        # Log
        self.label = QLabel()
        layout.addWidget(self.label)

        # Get key layout
        key_layout = QHBoxLayout()

        button_load_private_key = QPushButton("load private key")
        button_load_private_key.clicked.connect(self.load_private_key)
        key_layout.addWidget(button_load_private_key, 1)

        button_load_public_key = QPushButton("load public key")
        button_load_public_key.clicked.connect(self.load_public_key)
        key_layout.addWidget(button_load_public_key, 1)

        layout.addLayout(key_layout)

        # choose file layout
        file_layout = QHBoxLayout()

        button_choose_file = QPushButton("Choose file")
        button_choose_file.clicked.connect(self.setFile)
        file_layout.addWidget(button_choose_file, 1)

        self.file_input = QLineEdit()
        self.file_input.setReadOnly(True)
        self.file_input.setPlaceholderText("Select a file...")
        file_layout.addWidget(self.file_input, 6)

        layout.addLayout(file_layout)

        # Create a ecnrypt files layout
        crypt_layout = QHBoxLayout()

        button_encrypt = QPushButton("encrypt")
        button_encrypt.clicked.connect(self.encrypt)
        crypt_layout.addWidget(button_encrypt, 1)

        button_decrypt = QPushButton("decrypt")
        button_decrypt.clicked.connect(self.decrypt)
        crypt_layout.addWidget(button_decrypt, 1)

        layout.addLayout(crypt_layout)

        # signature layout
        signature_layout = QHBoxLayout()
        button_sign = QPushButton("generate signature")
        button_sign.clicked.connect(self.generate_signature)
        signature_layout.addWidget(button_sign)

        button_verify = QPushButton("verify signature")
        button_verify.clicked.connect(self.verify_signature)
        signature_layout.addWidget(button_verify)

        layout.addLayout(signature_layout)

        self.setLayout(layout)
        self.setWindowTitle('main app')
        self.show()

    def setFile(self):
        file_path = self.chooseFile()
        self.file_input.setText(file_path)

    def encrypt(self):
        if self.file_input.text() == '':
            self.show_error("You need to load a file first")
            return
        if self.public_key == None:
            self.show_error("You need to load public key first")
            return
        try:
            with open(self.file_input.text()) as f:
                content = f.read()
            content_bytes = content.encode("utf-8")
            rsa_key = RSA.import_key(self.public_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            cipher_bytes = cipher_rsa.encrypt(content_bytes)
            self.saveToFile(cipher_bytes, 'encrypted_file',
                            'save encrypted file')

        except Exception as e:
            self.show_error("Unexpected error occured")
            print(e)

    def decrypt(self):
        if self.file_input.text() == '':
            self.show_error("You need to load a file first")
            return
        if os.path.splitext(self.file_input.text())[-1] != '.bin':
            self.show_error("You need to specify a .bin file")
            return
        if self.private_key == None:
            self.show_error("You need to load private key first")
            return

        try:
            with open(self.file_input.text(), "rb") as f:
                ciphertext = f.read()

            rsa_key = RSA.import_key(self.private_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            decrypted_bytes = cipher_rsa.decrypt(ciphertext)

            # Write the decrypted content to the output file
            self.saveToFile(decrypted_bytes, 'decrypted_file',
                            'save decrypted file', filter=None)

        except Exception as e:
            self.show_error("Unexpected error occured")
            print(e)

    def load_public_key(self):
        key_file_path = self.chooseFile(file_filter="PEM Files (*.pem)")
        try:
            with open(key_file_path, "r") as file:
                key_string = file.read()
            if not is_rsa_public_key(key_string):
                self.show_error(
                    "The loaded file is not an RSA public key or it's a private key.")
                return
            self.public_key = key_string
            self.show_valid("Public key loaded succesfully")
        except OSError as e:
            print(e)
            self.show_error("Wrong file")
        except Exception as e:
            print(e)
            self.show_error("Unexpected error occured")

    def load_private_key(self):
        key_file_path = self.chooseFile(file_filter="PEM Files (*.pem)")
        try:
            with open(key_file_path, "r") as file:
                key_string = file.read()
            pin = self.show_pin_dialog()
            decrypted_key = decryptAES(pin, key_string)
            if not is_rsa_private_key(decrypted_key):
                self.show_error(
                    "The loaded file is not an RSA private key or it's a public key.")
                return
            self.private_key = decrypted_key
            self.show_valid("Private key loaded succesfully")
        except UnicodeDecodeError as e:
            print(e)
            self.show_error("Wrong pin")
        except OSError as e:
            print(e)
            self.show_error("Wrong file")
        except Exception as e:
            print(e)
            self.show_error("Unexpected error occured")

    def show_pin_dialog(self):
        pin, ok_pressed = QInputDialog.getText(self, "Enter PIN", "PIN:")
        if ok_pressed:
            return pin

    def show_error(self, text):
        self.label.setText(f"<font color='red'>{text}</font>")

    def show_valid(self, text):
        self.label.setText(f"<font color='green'>{text}</font>")

    def saveToFile(self, filecontents, name, title, filter="binary files (*.bin)"):
        file_path, _ = QFileDialog.getSaveFileName(
            self, title, name, filter)

        if file_path:
            # Write encrypted key to file
            with open(file_path, "wb") as file:
                file.write(filecontents)

    def chooseFile(self, file_filter=None):
        desktop_path = QStandardPaths.writableLocation(
            QStandardPaths.StandardLocation.DesktopLocation)

        response, _ = QFileDialog.getOpenFileName(
            parent=self,
            caption='Select a file',
            directory=desktop_path,
            filter=file_filter,
        )
        return response

    def generate_signature(self):
        if self.file_input.text() == '':
            self.show_error("You need to load a file first")
            return
        if self.private_key == None:
            self.show_error("You need to load private key first")
            return
        tree = create_signature(self.file_input.text(), self.private_key)
        file_path, _ = QFileDialog.getSaveFileName(
            self, 'save signature', 'signature', 'XML files (*.xml)')
        try:
            tree.write(file_path, encoding="utf-8", xml_declaration=True)
        except Exception as e:
            print(e)

    def verify_signature(self):
        if self.file_input.text() == '':
            self.show_error("You need to load a file first")
            return
        if self.private_key == self.public_key:
            self.show_error("You need to load public key first")
            return
        xml_file_path = self.chooseFile('XML files (*.xml)')
        try:
            if verify_signature(
                    xml_file_path, self.file_input.text(), self.public_key,self.private_key):
                self.show_valid("Signature good :)")
            else:
                self.show_error("Signature bad >:(")
        except ValueError as e:
            self.show_error("Hash element not found in the XML file")
            print(e)

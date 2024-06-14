import os
from PyQt6.QtWidgets import QWidget, QPushButton, QHBoxLayout, QFileDialog, QVBoxLayout, QTextEdit, QLineEdit, QInputDialog, QLabel
from PyQt6.QtCore import QStandardPaths
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from utils import create_signature, decryptAES, is_rsa_private_key, is_rsa_public_key, verify_signature
from file_checker import FileCheckerThread
from PyQt6.QtCore import pyqtSlot


class MainWindow(QWidget):
    PUBLIC_KEY_PATH = 'D:\public_key.pem'
    PRIVATE_KEY_PATH = 'D:\encrypted_private_key.pem'

    def __init__(self):
        super().__init__()
        self.window_width, self.window_height = 600, 200
        self.setMinimumSize(self.window_width, self.window_height)
        self.initUI()

        self.public_key_thread = FileCheckerThread(self.PUBLIC_KEY_PATH)
        self.public_key_thread.file_check_signal.connect(
            self.update_public_key_status)
        self.public_key_thread.start()

        self.private_key_thread = FileCheckerThread(self.PRIVATE_KEY_PATH)
        self.private_key_thread.file_check_signal.connect(
            self.update_private_key_status)
        self.private_key_thread.start()

        self.public_key_loaded = False
        self.private_key_loaded = False

    def initUI(self):
        layout = QVBoxLayout()

        # Log
        self.label = QLabel()
        layout.addWidget(self.label)

        key_status_layout = QHBoxLayout()

        self.public_key_status = QLabel("Checking file 1...", self)
        key_status_layout.addWidget(self.public_key_status)
        self.private_key_status = QLabel("Checking file 1...", self)
        key_status_layout.addWidget(self.private_key_status)
        layout.addLayout(key_status_layout)

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

    @pyqtSlot(bool)
    def update_public_key_status(self, file_exists):
        if file_exists:
            self.public_key_loaded = True
            self.public_key_status.setText(
                'Public key: <font color="green">Detected</font>')
        else:
            self.public_key_loaded = False
            self.public_key_status.setText(
                'Public key: <font color="red">Missing</font>')

    @pyqtSlot(bool)
    def update_private_key_status(self, file_exists):
        if file_exists:
            self.private_key_loaded = True
            self.private_key_status.setText(
                'Private key: <font color="green">Detected</font>')
        else:
            self.private_key_loaded = False
            self.private_key_status.setText(
                'Private key: <font color="red">Missing</font>')

    def setFile(self):
        file_path = self.chooseFile()
        self.file_input.setText(file_path)
        self.show_valid("File chosen successfully")

    def encrypt(self):
        try:
            public_key = self.load_public_key()
            try:
                with open(self.file_input.text()) as f:
                    content = f.read()
                content_bytes = content.encode("utf-8")
                rsa_key = RSA.import_key(public_key)
                cipher_rsa = PKCS1_OAEP.new(rsa_key)
                cipher_bytes = cipher_rsa.encrypt(content_bytes)
                self.saveToFile(cipher_bytes, 'encrypted_file',
                                'save encrypted file')
                self.show_valid("Encryption successful")
            except FileNotFoundError as e:
                self.show_error("No file provided")
                print(e)
            except Exception as e:
                self.show_error("Unexpected error occurred")
                print(e)
        except Exception as e:
            self.show_error(e)

    def decrypt(self):
        try:
            private_key = self.load_private_key()
            try:
                with open(self.file_input.text(), "rb") as f:
                    ciphertext = f.read()
                if os.path.splitext(self.file_input.text())[-1] != '.bin':
                    raise ValueError("Wrong file format (must be *.bin)")    
                rsa_key = RSA.import_key(private_key)
                cipher_rsa = PKCS1_OAEP.new(rsa_key)
                decrypted_bytes = cipher_rsa.decrypt(ciphertext)
                self.saveToFile(decrypted_bytes, 'decrypted_file',
                                'save decrypted file', filter=None)
                self.show_valid("Decryption successful")
            except ValueError as e:
                self.show_error(e)
            except FileNotFoundError as e:
                self.show_error("No file provided")
                print(e)
            except Exception as e:
                self.show_error("Unexpected error occurred")
                print(e)
        except Exception as e:
            self.show_error(e)

    def load_public_key(self):
        try:
            with open(self.PUBLIC_KEY_PATH, "r") as file:
                key_string = file.read()
            if not is_rsa_public_key(key_string):
                raise ValueError("Wrong key value")
        except FileNotFoundError:
            raise FileNotFoundError("Key not found")
        except ValueError:
            raise ValueError("Wrong key value")
        except Exception as e:
            print(e)
            raise Exception("Unexpected error occurred")

        return key_string

    def load_private_key(self):
        try:
            with open(self.PRIVATE_KEY_PATH, "r") as file:
                key_string = file.read()
            pin = self.show_pin_dialog()
            decrypted_key = decryptAES(pin, key_string)
            if not is_rsa_private_key(decrypted_key):
                raise ValueError("Wrong key value")
        except UnicodeDecodeError as e:
            raise Exception("Wrong pin")
        except FileNotFoundError:
            raise FileNotFoundError("Key not found")
        except ValueError:
            raise ValueError("Wrong key value")
        except Exception as e:
            print(e)
            raise Exception("Unexpected error occured")

        return decrypted_key

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
        current_dir = os.getcwd()

        response, _ = QFileDialog.getOpenFileName(
            parent=self,
            caption='Select a file',
            directory=current_dir,
            filter=file_filter,
        )
        return response

    def generate_signature(self):
        if self.file_input.text() == '':
            self.show_error("No file provided")
            return
        try:
            private_key = self.load_private_key()
            try:
                tree = create_signature(self.file_input.text(), private_key)
                file_path, _ = QFileDialog.getSaveFileName(
                    self, 'save signature', 'signature', 'XML files (*.xml)')
                tree.write(file_path, encoding="utf-8", xml_declaration=True)
                self.show_valid("Signing successful")
            except Exception as e:
                self.show_error("Unexpected error occurred")
        except Exception as e:
            self.show_error(e)
            
            
            
    def verify_signature(self):
        if self.file_input.text() == '':
            self.show_error("No file provided")
            return
        try:
            public_key = self.load_public_key()
            xml_file_path = self.chooseFile('XML files (*.xml)')
            try:
                if verify_signature(
                        xml_file_path, self.file_input.text(), public_key):
                    self.show_valid("Signature good :)")
                else:
                    self.show_error("Signature bad >:(")
            except ValueError as e:
                self.show_error("Hash element not found in the XML file")
                print(e)
        except Exception as e:
            self.show_error(e)

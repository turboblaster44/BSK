from PyQt6.QtWidgets import QWidget, QPushButton, QHBoxLayout, QFileDialog, QVBoxLayout, QTextEdit, QLineEdit
from PyQt6.QtCore import QStandardPaths

from utils import decryptAES, encryptAES, generateRSA


class KeyWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.window_width, self.window_height = 600, 200
        self.setMinimumSize(self.window_width, self.window_height)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # Create a button
        button = QPushButton('Generate RSA')
        button.clicked.connect(self.generateRSA)
        layout.addWidget(button)

        # Create a horizontal 2 text fields
        text_layout = QHBoxLayout()
        self.textF1 = QTextEdit()
        self.textF2 = QTextEdit()
        self.textF1.setReadOnly(True)
        self.textF2.setReadOnly(True)
        text_layout.addWidget(self.textF1)
        text_layout.addWidget(self.textF2)
        layout.addLayout(text_layout)

        # Create a horizontal layout for the small text input and button
        input_layout = QHBoxLayout()
        self.text_input = QLineEdit()
        self.text_input.setPlaceholderText("Enter 16 character PIN string")
        input_layout.addWidget(self.text_input)
        button2 = QPushButton('Encrypt')
        button2.clicked.connect(self.encrypt)
        input_layout.addWidget(button2)
        layout.addLayout(input_layout)

        # create output field
        self.textF3 = QTextEdit()
        self.textF3.setReadOnly(True)
        layout.addWidget(self.textF3)

        # save to file button
        save_layout = QHBoxLayout()
        button3 = QPushButton('Save encrypted private key')
        button3.clicked.connect(lambda: self.saveToFile(self.textF3,'encrypted_private_key'))
        save_layout.addWidget(button3)
        button4 = QPushButton('Save public key')
        button4.clicked.connect(lambda: self.saveToFile(self.textF2,'public_key'))
        save_layout.addWidget(button4)
        
        layout.addLayout(save_layout)

        self.setLayout(layout)
        self.setWindowTitle('Helper app')
        self.show()

    def generateRSA(self):
        private_key, public_key = generateRSA()
        self.textF1.setPlainText(private_key)
        self.textF2.setPlainText(public_key)

    def encrypt(self):
        pin = self.text_input.text()
        private_key = self.textF1.toPlainText()
        try:
            encoded_key = encryptAES(pin, private_key)
            self.textF3.setPlainText(encoded_key)
        except ValueError as e:
            self.textF3.setPlainText(str(e))
            return

    def saveToFile(self, field, name):
        encrypted_key = field.toPlainText()
        encrypted_key_bytes = encrypted_key.encode("utf-8")

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Encrypted Private Key", name, "PEM Files (*.pem)")

        if file_path:
            # Write encrypted key to file
            with open(file_path, "wb") as file:
                file.write(encrypted_key_bytes)

            print("Encrypted private key saved to:", file_path)

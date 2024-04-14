from window import Window
from PyQt6.QtWidgets import QApplication
import sys
from utils import decryptAES, encryptAES, pad_to_16_bytes


def main():
    s = 'Robie se przerzutke jak shimanoddadad'
    print(s)
    c = encryptAES('1234123412341234', s)
    a = decryptAES('1234123412341234', c)
    print(a)
    print(len(a))
    print(s)
    print(len(s))

    # app = QApplication(sys.argv)
    # window = Window()
    # window.show()
    # sys.exit(app.exec())
if __name__ == '__main__':
    main()

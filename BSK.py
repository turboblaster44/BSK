from key_window import KeyWindow
from main_window import MainWindow
from PyQt6.QtWidgets import QApplication
import sys


def main():
    windows = {
        'key': KeyWindow,
        'main': MainWindow
    }
    window_name = sys.argv[1]
    assert window_name in windows, "argument must be 'key' or 'main'"
    print(window_name)
    app = QApplication(sys.argv)
    window = windows[window_name]()
    window.show()
    sys.exit(app.exec())

def run_main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
if __name__ == '__main__':
    run_main()
    # assert len(sys.argv) == 2, "Only 1 argument is taken ('key' or 'main')"
    # main()

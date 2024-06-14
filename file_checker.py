import os
from PyQt6.QtCore import QThread, pyqtSignal

class FileCheckerThread(QThread):
    file_check_signal = pyqtSignal(bool)

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def run(self):
        while True:
            file_exists = os.path.exists(self.file_path)
            self.file_check_signal.emit(file_exists)
            self.sleep(1)
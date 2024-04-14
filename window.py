from PyQt6.QtWidgets import QWidget, QPushButton, QVBoxLayout, QFileDialog
from PyQt6.QtCore import QStandardPaths


class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.window_width, self.window_height = 400, 100
        self.setMinimumSize(self.window_width, self.window_height)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        self.setWindowTitle('BSK')

        button = QPushButton('Select File')
        button.clicked.connect(self.chooseFile)
        layout.addWidget(button)

    def chooseFile(self):
        file_filter = 'PDF Files (*.pdf);;C++ Files (*.cpp)'
        desktop_path = QStandardPaths.writableLocation(
            QStandardPaths.StandardLocation.DesktopLocation)

        response, _ = QFileDialog.getOpenFileName(
            parent=self,
            caption='Select a file',
            directory=desktop_path,
            filter=file_filter,
        )
        print(response)

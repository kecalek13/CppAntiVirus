import sys
import subprocess
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QWidget,
    QLabel,
    QTextEdit,
    QLineEdit,
    QComboBox,
    QFileDialog
)
from PyQt6.QtGui import QIcon

windowTitle = "C++ Antivirus"
windowWidth = 600
windowHeight = 400

executablePath = "C++AntivirusEngine.exe"  # Path to the C++ antivirus executable

pathToIcon = "../assets/icon.ico"  # Path to the icon file

class AntivirusGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle(windowTitle)
        self.setGeometry(100, 100, windowWidth, windowHeight)
        self.setWindowIcon(QIcon(pathToIcon))

        self.layout = QVBoxLayout()
        self.h_layout = QHBoxLayout()

        # ComboBox for scan type selection
        self.scanTypeLabel = QLabel("Select scan type:")
        self.scanTypeSelection = QComboBox()
        self.scanTypeSelection.addItem("Scan file")
        self.scanTypeSelection.addItem("Scan directory")
        self.scanTypeSelection.addItem("Scan all")
        self.scanTypeSelection.addItem("Scan disk")

        self.scanTypeSelection.currentTextChanged.connect(self.on_selection_change)

        self.layout.addWidget(self.scanTypeLabel)
        self.layout.addWidget(self.scanTypeSelection)

        # Input field for path/file/disk
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Enter path to file/directory or disk name")
        self.layout.addWidget(QLabel("Path or disk:"))
        self.h_layout.addWidget(self.path_input)


        # Button to browse for file/directory
        self.btn_file = QPushButton("Select file/directory", self)
        self.btn_file.clicked.connect(self.open_file_dialog)
        self.h_layout.addWidget(self.btn_file)

        self.layout.addLayout(self.h_layout)
        
        # Scan button
        self.button = QPushButton("Run scan")
        self.button.clicked.connect(self.run_antivirus)

        # Output
        self.output = QTextEdit()
        self.output.setReadOnly(True)

        self.layout.addWidget(self.button)
        self.layout.addWidget(self.output)
        self.setLayout(self.layout)

    def on_selection_change(self, selection):
        if selection == "Scan all":
            self.path_input.setDisabled(True)
            self.path_input.setText("")
            self.path_input.setPlaceholderText("")

            self.btn_file.setDisabled(True)
        elif selection == "Scan file":
            self.path_input.setDisabled(False)
            self.path_input.setText("")
            self.path_input.setPlaceholderText("C:/path/to/any.file")

            self.btn_file.setDisabled(False)
        elif selection == "Scan directory":
            self.path_input.setDisabled(False)
            self.path_input.setText("")
            self.path_input.setPlaceholderText("C:/path/to/directory")

            self.btn_file.setDisabled(False)
        elif selection == "Scan disk":
            self.path_input.setDisabled(False)
            self.path_input.setText("")
            self.path_input.setPlaceholderText("C:/ or D:/ or E:/ etc.")

            self.btn_file.setDisabled(True)

    def open_file_dialog(self):
        # Open file dialog to select a file
        if self.scanTypeSelection.currentText() == "Scan file":
            file_name, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
            if file_name:
                self.path_input.setText(file_name)
        elif self.scanTypeSelection.currentText() == "Scan directory":
            dir_name = QFileDialog.getExistingDirectory(self, "Select Directory", "")
            if dir_name:
                self.path_input.setText(dir_name)

    def run_antivirus(self):
        # Run the C++ antivirus executable

        selected = self.scanTypeSelection.currentText()
        path = self.path_input.text()

        if selected == "Scan file":
            try:
                self.scan_process = subprocess.run([executablePath, "--scan-file", path], capture_output=True, text=True)
                self.output.setText(self.scan_process.stdout if self.scan_process.returncode == 0 else self.scan_process.stderr)
            except FileNotFoundError:
                self.output.setText("C++Antivirus.exe wasn't find.")
        elif selected == "Scan directory":
            try:
                self.scan_process = subprocess.run([executablePath, "--scan-dir", path], capture_output=True, text=True)
                self.output.setText(self.scan_process.stdout if self.scan_process.returncode == 0 else self.scan_process.stderr)
            except FileNotFoundError:
                self.output.setText("C++Antivirus.exe wasn't find.")
        elif selected == "Scan disk":
            try:
                self.scan_process = subprocess.run([executablePath, "--scan-disk", path], capture_output=True, text=True)
                self.output.setText(self.scan_process.stdout if self.scan_process.returncode == 0 else self.scan_process.stderr)
            except FileNotFoundError:
                self.output.setText("C++Antivirus.exe wasn't find.")
        elif selected == "Scan all":
            try:
                self.scan_process = subprocess.run([executablePath, "--scan-all", "-"], capture_output=True, text=True)
                self.output.setText(self.scan_process.stdout if self.scan_process.returncode == 0 else self.scan_process.stderr)
            except FileNotFoundError:
                self.output.setText("C++Antivirus.exe wasn't find.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = AntivirusGUI()
    gui.show()
    sys.exit(app.exec())
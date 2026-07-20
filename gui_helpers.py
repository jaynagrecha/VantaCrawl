import asyncio
import sys

from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QApplication, QMainWindow

from crawler_common import DownloadManager, get_project_paths, normalize_extensions, run_bfs_crawl_async


class AsyncCrawlerThread(QThread):
    update_output = pyqtSignal(str)
    update_progress = pyqtSignal(int, int, str)
    finished_crawling = pyqtSignal()

    def __init__(
        self,
        url,
        wordlist_file,
        download_files=False,
        extensions=None,
        restrict_domain=True,
        max_depth=3,
        page_html_fetcher=None,
    ):
        super().__init__()
        self.url = url
        self.wordlist_file = wordlist_file
        self.download_files = download_files
        self.extensions = normalize_extensions(extensions)
        self.restrict_domain = restrict_domain
        self.max_depth = max_depth
        self.page_html_fetcher = page_html_fetcher
        self._is_running = True
        self.manager = DownloadManager()
        _, self.output_file_path, self.download_dir = get_project_paths()

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            open(self.output_file_path, "w", encoding="utf-8").close()
            loop.run_until_complete(
                run_bfs_crawl_async(
                    self.url,
                    self.wordlist_file,
                    self.append,
                    self.is_running,
                    self.output_file_path,
                    restrict_domain=self.restrict_domain,
                    download_files=self.download_files,
                    download_dir=self.download_dir,
                    update_progress=self.update_progress,
                    manager=self.manager,
                    extensions=self.extensions,
                    max_depth=self.max_depth,
                    page_html_fetcher=self.page_html_fetcher,
                )
            )
        finally:
            loop.close()
            self.finished_crawling.emit()

    def stop(self):
        self._is_running = False
        self.manager.cancel_all()

    def is_running(self):
        return self._is_running

    def append(self, message):
        self.update_output.emit(str(message))


class SyncCrawlerThread(QThread):
    update_output = pyqtSignal(str)
    update_progress = pyqtSignal(int, int, str)
    finished_crawling = pyqtSignal()

    def __init__(
        self,
        url,
        wordlist_file,
        restrict_domain=True,
        download_files=False,
        extensions=None,
        max_depth=1,
    ):
        super().__init__()
        self.url = url
        self.wordlist_file = wordlist_file
        self.restrict_domain = restrict_domain
        self.download_files = download_files
        self.extensions = normalize_extensions(extensions)
        self.max_depth = max_depth
        self._is_running = True
        _, self.output_file_path, self.download_dir = get_project_paths()

    def run(self):
        from crawler_common import run_bfs_crawl_sync

        open(self.output_file_path, "w", encoding="utf-8").close()

        def progress_callback(total_size, downloaded_size, size_text):
            self.update_progress.emit(total_size, downloaded_size, size_text or "")

        run_bfs_crawl_sync(
            self.url,
            self.wordlist_file,
            self.append,
            self.is_running,
            self.output_file_path,
            restrict_domain=self.restrict_domain,
            download_files=self.download_files,
            download_dir=self.download_dir,
            update_progress=progress_callback if self.download_files else None,
            extensions=self.extensions,
            max_depth=self.max_depth,
        )
        self.finished_crawling.emit()

    def stop(self):
        self._is_running = False

    def is_running(self):
        return self._is_running

    def append(self, message):
        self.update_output.emit(str(message))


def build_async_app_window(
    title,
    include_download_mode=False,
    include_extensions=False,
    restrict_domain=True,
    max_depth=3,
    page_html_fetcher=None,
    default_download_files=False,
):
    from PyQt5.QtWidgets import (
        QFileDialog,
        QLabel,
        QLineEdit,
        QProgressBar,
        QPushButton,
        QRadioButton,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )

    _, output_file_path, _ = get_project_paths()

    class CrawlerApp(QMainWindow):
        def __init__(self):
            super().__init__()
            self.crawler_thread = None
            self.wordlist_file = None
            self.initUI()

        def initUI(self):
            self.setWindowTitle(title)
            self.setGeometry(100, 100, 800, 600)

            central_widget = QWidget(self)
            self.setCentralWidget(central_widget)
            layout = QVBoxLayout()
            central_widget.setLayout(layout)

            if include_download_mode:
                self.crawl_only_radio = QRadioButton("Crawl and Brute Force (No Download)")
                self.crawl_only_radio.setChecked(True)
                self.download_radio = QRadioButton("Crawl, Brute Force and Download")
                layout.addWidget(self.crawl_only_radio)
                layout.addWidget(self.download_radio)

            self.url_input = QLineEdit(self)
            self.url_input.setPlaceholderText("Enter the URL to crawl")
            layout.addWidget(QLabel("URL:"))
            layout.addWidget(self.url_input)

            self.wordlist_button = QPushButton("Select Wordlist File", self)
            self.wordlist_button.clicked.connect(self.select_wordlist)
            layout.addWidget(self.wordlist_button)

            self.wordlist_label = QLabel("No wordlist selected", self)
            layout.addWidget(self.wordlist_label)

            if include_extensions:
                self.extensions_input = QLineEdit(self)
                self.extensions_input.setPlaceholderText("Enter file extensions (e.g., .pdf,.jpg,.txt)")
                layout.addWidget(QLabel("File Extensions:"))
                layout.addWidget(self.extensions_input)

            self.start_button = QPushButton("Start Crawling", self)
            self.start_button.clicked.connect(self.start_crawling)
            layout.addWidget(self.start_button)

            self.stop_button = QPushButton("Stop Crawling", self)
            self.stop_button.clicked.connect(self.stop_crawling)
            self.stop_button.setEnabled(False)
            layout.addWidget(self.stop_button)

            self.output_text = QTextEdit(self)
            self.output_text.setReadOnly(True)
            layout.addWidget(self.output_text)

            self.progress_bar = QProgressBar(self)
            layout.addWidget(QLabel("Download Progress:"))
            layout.addWidget(self.progress_bar)

            self.size_label = QLabel("Size: N/A", self)
            layout.addWidget(self.size_label)

        def select_wordlist(self):
            file_name, _ = QFileDialog.getOpenFileName(
                self,
                "Select Wordlist File",
                "",
                "Text Files (*.txt);;All Files (*)",
            )
            if file_name:
                self.wordlist_label.setText(file_name)
                self.wordlist_file = file_name

        def start_crawling(self):
            url = self.url_input.text().strip()
            if not url:
                self.output_text.append("Please enter a valid URL.")
                return
            if not self.wordlist_file:
                self.output_text.append("Please select a wordlist file.")
                return

            extensions = None
            if include_extensions:
                extensions = [
                    item.strip()
                    for item in self.extensions_input.text().lower().split(",")
                    if item.strip()
                ]

            download_files = default_download_files
            if include_download_mode:
                download_files = self.download_radio.isChecked()

            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)

            self.crawler_thread = AsyncCrawlerThread(
                url,
                self.wordlist_file,
                download_files=download_files,
                extensions=extensions,
                restrict_domain=restrict_domain,
                max_depth=max_depth,
                page_html_fetcher=page_html_fetcher,
            )
            self.crawler_thread.update_output.connect(self.update_output_text)
            self.crawler_thread.update_progress.connect(self.update_progress)
            self.crawler_thread.finished_crawling.connect(self.finished_crawling)
            self.crawler_thread.start()

        def stop_crawling(self):
            if self.crawler_thread:
                self.crawler_thread.stop()
                self.output_text.append("\nCrawling has been stopped by the user.")

        def update_output_text(self, message):
            self.output_text.append(message)

        def update_progress(self, total_size, downloaded_size, size_text):
            if size_text:
                self.size_label.setText(size_text)
            if total_size > 0:
                self.progress_bar.setValue(int((downloaded_size / total_size) * 100))
            else:
                self.progress_bar.setValue(0)

        def finished_crawling(self):
            self.output_text.append(f"\nCrawling complete. Results saved to {output_file_path}.")
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.progress_bar.setValue(0)
            self.size_label.setText("Size: N/A")

        def closeEvent(self, event):
            if self.crawler_thread and self.crawler_thread.isRunning():
                self.crawler_thread.stop()
                self.crawler_thread.wait(5000)
                self.output_text.append("\nCrawling has been stopped because the application is closing.")
            event.accept()

    return CrawlerApp


def build_sync_app_window(title, restrict_domain=True, download_files=False, max_depth=1, show_progress=True):
    from PyQt5.QtWidgets import (
        QFileDialog,
        QLabel,
        QLineEdit,
        QProgressBar,
        QPushButton,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )

    _, output_file_path, _ = get_project_paths()

    class CrawlerApp(QMainWindow):
        def __init__(self):
            super().__init__()
            self.crawler_thread = None
            self.wordlist_file = None
            self.initUI()

        def initUI(self):
            self.setWindowTitle(title)
            self.setGeometry(100, 100, 800, 600)

            central_widget = QWidget(self)
            self.setCentralWidget(central_widget)
            layout = QVBoxLayout()
            central_widget.setLayout(layout)

            self.url_input = QLineEdit(self)
            self.url_input.setPlaceholderText("Enter the URL to crawl")
            layout.addWidget(QLabel("URL:"))
            layout.addWidget(self.url_input)

            self.wordlist_button = QPushButton("Select Wordlist File", self)
            self.wordlist_button.clicked.connect(self.select_wordlist)
            layout.addWidget(self.wordlist_button)

            self.wordlist_label = QLabel("No wordlist selected", self)
            layout.addWidget(self.wordlist_label)

            self.start_button = QPushButton("Start Crawling", self)
            self.start_button.clicked.connect(self.start_crawling)
            layout.addWidget(self.start_button)

            self.stop_button = QPushButton("Stop Crawling", self)
            self.stop_button.clicked.connect(self.stop_crawling)
            self.stop_button.setEnabled(False)
            layout.addWidget(self.stop_button)

            self.output_text = QTextEdit(self)
            self.output_text.setReadOnly(True)
            layout.addWidget(self.output_text)

            if show_progress:
                self.progress_bar = QProgressBar(self)
                layout.addWidget(QLabel("Download Progress:"))
                layout.addWidget(self.progress_bar)
                self.size_label = QLabel("Size: N/A", self)
                layout.addWidget(self.size_label)

        def select_wordlist(self):
            file_name, _ = QFileDialog.getOpenFileName(
                self,
                "Select Wordlist File",
                "",
                "Text Files (*.txt);;All Files (*)",
            )
            if file_name:
                self.wordlist_label.setText(file_name)
                self.wordlist_file = file_name

        def start_crawling(self):
            url = self.url_input.text().strip()
            if not url:
                self.output_text.append("Please enter a valid URL.")
                return
            if not self.wordlist_file:
                self.output_text.append("Please select a wordlist file.")
                return

            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)

            self.crawler_thread = SyncCrawlerThread(
                url,
                self.wordlist_file,
                restrict_domain=restrict_domain,
                download_files=download_files,
                max_depth=max_depth,
            )
            self.crawler_thread.update_output.connect(self.update_output_text)
            if show_progress:
                self.crawler_thread.update_progress.connect(self.update_progress)
            self.crawler_thread.finished_crawling.connect(self.finished_crawling)
            self.crawler_thread.start()

        def stop_crawling(self):
            if self.crawler_thread:
                self.crawler_thread.stop()
                self.output_text.append("\nStopping the crawling process...")

        def update_output_text(self, message):
            self.output_text.append(message)

        def update_progress(self, total_size, downloaded_size, size_text):
            if show_progress:
                if size_text:
                    self.size_label.setText(size_text)
                if total_size > 0:
                    self.progress_bar.setValue(int((downloaded_size / total_size) * 100))
                else:
                    self.progress_bar.setValue(0)

        def finished_crawling(self):
            self.output_text.append(f"\nCrawling complete. Results saved to {output_file_path}.")
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            if show_progress:
                self.progress_bar.setValue(0)
                self.size_label.setText("Size: N/A")

        def closeEvent(self, event):
            if self.crawler_thread and self.crawler_thread.isRunning():
                self.crawler_thread.stop()
                self.crawler_thread.wait(5000)
                self.output_text.append("\nCrawling has been stopped because the application is closing.")
            event.accept()

    return CrawlerApp


def run_sync_gui(app_class):
    app = QApplication(sys.argv)
    window = app_class()
    window.show()
    sys.exit(app.exec_())


def run_async_gui(app_class):
    app = QApplication(sys.argv)
    window = app_class()
    window.show()
    sys.exit(app.exec_())

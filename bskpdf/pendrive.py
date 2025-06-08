import os
import threading
import time

from pathlib import Path
from typing import Callable

class Pendrive:
    """
    Monitor the connection status of a pendrive at a specified path.
    Callback functions can be set to handle attach and detach events.

    :param path: The filesystem path to monitor for the pendrive.
    """
    def __init__(self, path: "str | os.PathLike[str]"):
        self.path = path
        self._thread = threading.Thread(target=self._checker_task, daemon=True)
        self.attach: None | Callable[[str], None] = None
        self.detach: None | Callable[[str], None] = None
        self.attached = False

    def run(self):
        """
        Start the background thread that monitors the pendrive status.
        This method returns immediately.
        """
        self._thread.start()

    def _checker_task(self):
        """
        Periodically check for the presence of the pendrive.
        Invokes attach or detach callbacks based on connection status.
        Intended to run in a background thread.
        """
        while True:
            time.sleep(0.1)

            if not self.attached and Path(self.path).exists():
                self.attached = True
                if self.attach is not None:
                    self.attach(self.path)

            if self.attached and not Path(self.path).exists():
                self.attached = False
                if self.detach is not None:
                    self.detach(self.path)

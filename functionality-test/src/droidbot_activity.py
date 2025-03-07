import os
import subprocess
from typing import List
from time import sleep
from tool import Adb
from loguru import logger

class DroidbotActivation:
    """
    This class defines droidbot features
    """

    def __init__(self, timeout: int, device: str, output_dir: str, droidbot_args: list, log) -> None:
        """

        Parameters
        ----------
        timeout : int
            timeout set for droidbot running
        device : str
            device id where to install and instrument an apk
        output_dir : str
            droidbot output directory
        droidbot_args : list
            droidbot arguments from https://github.com/honeynet/droidbot/tree/master
        log : Logger
            logger where to log monitoring process
        """

        self.timeout = timeout
        self.device = device
        self.output_dir = output_dir
        self.droidbot_args = droidbot_args
        self.log = logger
        self.adb = Adb(device)
    

    def _start_droidbot(self, apk_path: str) -> int:
        """

        Parameters
        ----------
            apk_path : str
                path of the apk to execute and instrument with droidbot

        Returns
        ----------
            int: pid of droidbot subprocess
        """
        apk_sha = os.path.split(apk_path[-1]).replace('.apk', '')
        output_dir = os.path.join(self.output_dir, apk_sha, 'droidbot')
        start_cmd = List[str] = [
            "droidbot",
            "-timeout",
            self.timeout,
            "-d",
            self.device,
            "-o",
            output_dir,
            *self.droidbot_args,
            "-a",
            apk_path
        ]
        start_cmd = " ".join(start_cmd)

        process = subprocess.Popen(start_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return process

    def run_droidbot(self, apk_path: str) -> int:
        """

        run application "apk_path" through droidbot

        Args:
            apk_path (str): path of the apk to execute and instrument with droidbot

        Returns:
            int: pid of droidbot subprocess
        """
        try:
            p_droidbot = self._start_droidbot(apk_path)
            sleep(20)   # Wait for Droitbot to complete initialization
            return p_droidbot
        except Exception as e:
            self.log.error(f"run droidbot interrupted due to {e}")

    def kill(self, pkg_name: str) -> None:
        """

        kill droidbot and instrumented application

        Parameters
        ----------
        pkg_name : str
            package name of the instrumented application
        """
        
        try:
            self.adb.uninstall_pkg(self.device, "io.github.ylimit.droidbotapp")
            self.adb.uninstall_pkg(self.device, pkg_name)
            self.log.info("droidbot and application to instrument is killed")
        except Exception as e:
            self.log.error(f"kill droidbot process interrupted due to {e}")

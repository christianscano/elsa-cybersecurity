from typing import List
import subprocess, os
import shutil

class Adb:
    """
    this class aggregates adb functionalities
    """

    def __init__(self, device: str) -> None:
        
        """
        
        Parameters
        ----------
        device : str
            device ID to connect with adb

        Raises
        ------
        RuntimeError
            raisen when adb is not found
        """
        
        self.adb_path = "adb"
        
        full_adb_path = shutil.which(self.adb_path)
        if full_adb_path is None:
            raise RuntimeError(
                f"Something is wrong with {self.adb_path}"
            )
        else:
            self.adb_path = full_adb_path
        
        self.device = device


    def get_pid(self, pkg_name: str) -> str|None:
        """
        get process id of the running application

        Parameters
        ----------
        pkg_name : str
            package name to uninstall

        Returns
        -------
        str|None
             process id of the running application
        """
    
        cmd: List[str] = [
            self.adb_path,
            "-s",
            self.device,
            "shell",
            "\"ps | grep",
            pkg_name+"\""
        ]
        cmd = " ".join(cmd)
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        output = stdout.decode('utf-8').split()
        try:
            pid = output[-1]
            return pid
        except:
            return None
    
    def push_file(self, file_path: str, directory: str) -> None:

        """

        push a file inside a device

        Parameters
        ----------
        file_path : str
            file_path to push
        directory:
            directory where to push the file
        """

        cmd: List[str] = [
            self.adb_path,
            "-s",
            self.device,
            "push",
            file_path,
            directory
        ]
        # cmd = " ".join(cmd)
        # os.system(cmd)
        subprocess.call(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    
    def pull_file(self, file_path: str, directory: str) -> None:

        """

        pull a file from a device

        Parameters
        ----------
        file_path : str
            file_path to pull
        directory:
            directory where to pull the file
        """

        cmd: List[str] = [
            self.adb_path,
            "-s",
            self.device,
            "pull",
            file_path,
            directory
        ]
        # cmd = " ".join(cmd)
        # os.system(cmd)
        subprocess.call(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


    def chmod(self, file_path: str, permissions: str) -> None:
        """
        chmod for a file in a device

        Parameters
        ----------
        file_path : str
            file_path to push
        permissions : str
            permissions to give to the file
        """

        cmd: List[str] = [
            self.adb_path,
            "-s",
            self.device,
            "shell",
            "chmod",
            permissions,
            file_path
        ]
        # cmd = " ".join(cmd)
        # os.system(cmd)
        subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    
    def execute_file(self, file_path: str) -> None:
        """
        chmod for a file in a device

        Parameters
        ----------
        file_path : str
            file_path to push
        """

        cmd: List[str] = [
            self.adb_path,
            "-s",
            self.device,
            "shell",
            "su",
            "0",
            "sh",
            "-c",
            f"'{file_path} &'"
        ]
        # cmd = " ".join(cmd)
        print(cmd)
        # os.system(cmd)
        # print(cmd)
        subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    def _get_ui_xml(self, file_path: str, destination: str) -> None:
        """
        get the UI xml

        Parameters
        ----------
        file_path : str
            file path where to save remotely (locally to device) the UI
        destination : str
            destination where to save on the pc the UI
        """

        # dump the xml
        cmd: List[str] = [
            self.adb_path,
            "-s",
            self.device,
            "shell",
            "uiautomator",
            "dump",
            file_path
        ]
        subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        self.pull_file(file_path, destination)
        return destination
    
    @staticmethod
    def _check_install_popup(file_path: str) -> bool:
        """
        check the presence of the installation popup

        Parameters
        ----------
        file_path : str
            file path of the UI to read

        Returns
        -------
        bool
            True if the popus USB install is present, False otherwise
        """

        with open(file_path, "r", encoding="utf-8") as file:
            return "Installa tramite USB" in file.read()
    
    def touch_screen(self, x: str, y: str) -> None:
        """
        touch the screen at coordinates (x, y)

        Parameters
        ----------
        x : int
            x coordinate of the screen
        y : int
            y coordinate of the screen
        """
        
        cmd: List[str] = [
            self.adb_path,
            "-s",
            self.device,
            "shell",
            "input",
            "tap",
            x,
            y
        ]

        subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    
    def install_apk(self, path_app: str) -> None:
        """
        Install app given its path

        Parameters
        ----------
        path_app : str
            path of the application to install
        """

        cmd: List[str] = [
            self.adb_path,
            "-s",
            self.device,
            "install",
            path_app
        ]

        subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        self._get_ui_xml('/sdcard/ui_dump.xml', ".")
        # if the installation popup is present touch Install
        if self._check_install_popup('./ui_dump.xml'):
            self.touch_screen("293", "2062")

        
    def uninstall_pkg(self, pkg_name: str) -> None:
        """
        Uninstall app by pkg_name

        Parameters
        ----------
        pkg_name : str
            package name to uninstall
        """
        cmd: List[str] = [
            self.adb_path,
            "-s",
            self.device,
            "uninstall",
            pkg_name
        ]

        # subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
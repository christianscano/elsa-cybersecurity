from typing import List
import subprocess, os
import shutil

class Adb:
    """
    this class aggregates adb functionalities
    """

    def __init__(self):
        
        
        self.adb_path = "adb"
        
        full_adb_path = shutil.which(self.adb_path)
        if full_adb_path is None:
            raise RuntimeError(
                f"Something is wrong with {self.adb_path}"
            )
        else:
            self.adb_path = full_adb_path


    def get_pid(self, device: str, pkg_name: str) -> str|None:
        """
        get process id of the running application

        Parameters
        ----------
        device : str
            device id where to uninstall the application
        pkg_name : str
            package name to uninstall

        Returns
        -------
        str|None
             process id of the running application
        """
    
        cmd = List[str] = [
            self.adb_path,
            "-s",
            device,
            "shell",
            "ps | grep",
            pkg_name
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
    
    def push_file(self, device: str, file_path: str, directory: str) -> None:

        """

        push a file inside a device

        Parameters
        ----------
        device : str
            device id where to uninstall the application
        file_path : str
            file_path to push
        directory:
            directory where to push the file
        """

        cmd = List[str] = [
            self.adb_path,
            "-s",
            device,
            "push",
            file_path,
            directory
        ]
        # cmd = " ".join(cmd)
        # os.system(cmd)
        subprocess.call(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    
    def chmod(self, device: str, file_path: str, permissions: str):
        """
        chmod for a file in a device

        Parameters
        ----------
        device : str
            device id where to uninstall the application
        file_path : str
            file_path to push
        permissions : str
            permissions to give to the file
        """

        cmd = List[str] = [
            self.adb_path,
            "-s",
            device,
            "shell",
            "chmod",
            permissions,
            file_path
        ]
        # cmd = " ".join(cmd)
        # os.system(cmd)
        subprocess.call(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    
    def execute_file(self, device: str, file_path: str):
        """
        chmod for a file in a device

        Parameters
        ----------
        device : str
            device id where to uninstall the application
        file_path : str
            file_path to push
        """

        cmd = List[str] = [
            self.adb_path,
            "-s",
            device,
            "su 0 sh -c",
            f"'{file_path} &'"
        ]
        # cmd = " ".join(cmd)
        # os.system(cmd)
        subprocess.call(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        
    def uninstall_pkg(self, device: str, pkg_name: str):
        """
        Uninstall app by pkg_name

        Args:
            device : str
                device id where to uninstall the application
            pkg_name : str
                package name to uninstall
        """
        cmd = List[str] = [
            self.adb_path,
            "-s",
            device,
            "uninstall",
            pkg_name
        ]

        subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
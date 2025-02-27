from typing import List
import subprocess, os
import shutil

class Adb:
    """
    this class aggregates adb functionalities
    """

    def __init__(self, device):
        
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
    
        cmd = List[str] = [
            self.adb_path,
            "-s",
            self.device,
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

        cmd = List[str] = [
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
    
    def chmod(self, file_path: str, permissions: str):
        """
        chmod for a file in a device

        Parameters
        ----------
        file_path : str
            file_path to push
        permissions : str
            permissions to give to the file
        """

        cmd = List[str] = [
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
    
    def execute_file(self, file_path: str):
        """
        chmod for a file in a device

        Parameters
        ----------
        file_path : str
            file_path to push
        """

        cmd = List[str] = [
            self.adb_path,
            "-s",
            self.device,
            "su 0 sh -c",
            f"'{file_path} &'"
        ]
        # cmd = " ".join(cmd)
        # os.system(cmd)
        subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        
    def uninstall_pkg(self, pkg_name: str):
        """
        Uninstall app by pkg_name

        Parameters
        ----------
        pkg_name : str
            package name to uninstall
        """
        cmd = List[str] = [
            self.adb_path,
            "-s",
            self.device,
            "uninstall",
            pkg_name
        ]

        # subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
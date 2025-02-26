from typing import List
import subprocess
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
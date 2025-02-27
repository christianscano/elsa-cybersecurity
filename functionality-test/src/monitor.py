import subprocess
from tool import Adb
import os, threading
from loguru import Logger
from typing import List, Tuple
import shutil
from jinja2 import Template
from androguard.misc import AnalyzeAPK

class FridaMonitor:

    """
    this class monitors the API calls
    """

    def __init__(self, device: str, frida_server: str, logger: Logger, output_dir: str):
        """

        Parameters
        ----------
        device : str
            device id where to run frida and the instrumented application
        frida_server : str
            path frida server to run in the device to hook APIs
        logger : Logger
            logger where to log monitoring process
        output_dir : str
            path of the monitoring output
        """
        
        self.device = device
        self.frida_server = frida_server
        self.logger = logger
        self.output_dir = output_dir
        self.script = None

        self.frida_path = "frida"
        full_frida_path = shutil.which(self.frida_path)
        if full_frida_path is None:
            raise RuntimeError(
                f"Something is wrong with {self.frida_path}"
            )
        else:
            self.frida_path = full_frida_path
        
        self.device = device
        self.adb = Adb(device)

    
    def start_frida(self):
        """
        start the frida server in the device
        """

        try:
            if self.adb.get_pid(pkg_name='frida-server') is None:
                # push frida-server in /data/local/tmp
                self.adb.push_file(directory='/data/local/tmp', file_path=self.frida_server)
                # make frida-server executable
                self.adb.chmod(file_path=f'/data/local/tmp/{self.frida_server}', permissions='755')
                # execute frida-server
                self.adb.execute_file(file_path=f'/data/local/tmp/{self.frida_server}')
                if self.adb.get_pid(pkg_name='frida-server'):
                    self.logger.info("frida-server is up and running")
            else:
                self.logger.info("frida-server is up and running")
        except Exception as e:
            self.logger.error(f"start_frida interrupted due to {e}")

    @staticmethod
    def _parse_manifest(apk_path: str) -> Tuple[List, str]:
        """
        parse the manifest of the apk to hook

        Parameters
        ----------
        apk_path : str
            path of the apk to hook

        Returns
        -------
        Tuple[List, str]
            List of the components to hook, package name of the apk
        """
        a, _, _ = AnalyzeAPK(apk_path)
        components = a.get_activities()
        components += a.get_receivers()
        components += a.get_providers()
        components += a.get_services()

        return components, a.get_package()

    @staticmethod
    def _get_apk_sha(apk_path: str) -> str:
        """
        get apk sha256 from the apk path

        Parameters
        ----------
        apk_path : str
            path of the apk to hook

        Returns
        -------
        str
            sha256 of the apk to hook
        """

        apk_sha = os.path.split(apk_path)[-1].replace('.apk', '')
        return apk_sha

    def _build_scrit(self, components: List, apk_sha: str):
        """
        Build script of API Hooking

        Parameters
        ----------
        components : List
            components where to start the hooking
        apk_sha : str
            sha256 of the apk to hook
        """

        with open("scripts/Api_Hook.js", "r") as file:
            js_template = file.read()

        data = {
            "components": components
        }

        # inject the template of the base Api_hook script
        template = Template(js_template)
        filled_js = template.render(data)
        self.script = os.join(self.output_dir, apk_sha, "frida", "API_hook.js")

        with open(self.script, "w") as file:
            file.write(filled_js)

    
    def build_script(self, apk_path: str) -> str:
        """
        Build script of API Hooking

        Parameters
        ----------
        apk_sha : str
            sha256 of the apk to hook

        Returns
        ------- 
        str  
            package name of the apk to hook
        """

        components, pkg_name = self._parse_manifest(apk_path)
        apk_sha = self._get_apk_sha(apk_path)
        self._build_scrit(components, apk_sha)
        return pkg_name

    def attach(self, apk_path: str, pkg_name: str, idx: int) -> Tuple[int, str]:
        """
        attach to frida server to hook APIs based on the script

        Parameters
        ----------
        apk_path : str
            path of the apk to hook
        pkg_name : str
            package name of the apk to hook
        idx : int
            index of the frida run

        Returns
        -------
        Tuple[int, str]
            frida process, file pointer of the output
        """

        apk_sha = self._get_apk_sha(apk_path)
        output_path = os.join(self.output_dir, apk_sha, "frida")
        if not os.path.exists(output_path):
            os.mkdir(output_path)

        output_path = os.path.join(output_path, f'monitoring{idx}.txt')
        pid = self.adb.get_pid(pkg_name)

        cmd = List[str] = [
            self.frida_path,
            "-D",
            self.device,
            "-l",
            self.script,
            "-p",
            pid,
            "--no-pause"
        ]
        fp = open(output_path, 'w')
        process = subprocess.Popen(cmd, stdout=fp, stderr=subprocess.DEVNULL)
        self.logger.info(f"frida is attached and hooking APIs for {apk_path}")
        return process.pid, fp

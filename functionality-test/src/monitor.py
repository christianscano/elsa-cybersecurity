import subprocess
from tool import Adb
import os, threading
from loguru import logger
from typing import List, Tuple
import shutil
from jinja2 import Template
from androguard.misc import AnalyzeAPK
from time import sleep
import psutil

exclude_classes = ['android.support', 'android.content', 'android.widget', 'android.graphics', 'android.canvas',
                   'android.view', 'android.util', 'android.animation', 'android.webkit','java.util', 'java.math', 
                   'java.nio', 'java.io', 'java.lang']

class FridaMonitor:

    """
    this class monitors the API calls
    """

    def __init__(self, device: str, frida_server: str, log, output_dir: str) -> None:
        """

        Parameters
        ----------
        device : str
            device id where to run frida and the instrumented application
        frida_server : str
            path frida server to run in the device to hook APIs
        log : Logger
            logger where to log monitoring process
        output_dir : str
            path of the monitoring output
        """
        
        self.device = device
        self.frida_server = frida_server
        self.log = log
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

    
    def start_frida(self) -> None:
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
                    self.log.info("frida-server is up and running")
            else:
                self.log.info("frida-server is up and running")
        except Exception as e:
            self.log.error(f"start_frida interrupted due to {e}")

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
    def _parse_apk(apk_path: str) -> Tuple[List, str]:
        """
        parse apk to get APIs to hook

        Parameters
        ----------
        apk_path : str
            path of the apk to hook

        Returns
        -------
        Tuple[List, str]
            List of the api classes to hook, package name of the apk
        """

        classes = set()
        a, d, dx = AnalyzeAPK(apk_path)
        # Iterate over the classes
        for d1 in d: 
            for cls in d1.get_classes():
                class_name = cls.get_name()
                
                # Iterate over methods in the class
                for method in cls.get_methods():
                    method_name = method.get_name()

                    # Get called methods in the current method
                    g = dx.get_method_analysis(method)
                    
                    if g is not None:
                        # Analyze each instruction and detect method calls
                        for _, call, _ in g.get_xref_to():
                            called_method = call.get_class_name()
                            classes.add(str(called_method[:-1]))
        classes = set([c[1:].replace('/', '.') for c in classes])
        filtered_classes = set()
        for c in classes:
            if '.'.join(c.split('.', 2)[:2]) not in exclude_classes: 
                if 'android' in c.split('.')[0] or 'java' in c.split('.')[0] :
                    filtered_classes.add(c)

        return filtered_classes, a.get_package()

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

    def _build_script(self, components: List, apk_sha: str) -> None:
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

    
    def build_script_from_components(self, apk_path: str) -> str:
        """
        Build script of API Hooking from app components

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
        self._build_script(components, apk_sha)
        return pkg_name
    
    def build_script_from_apis(self, apk_path: str) -> str:
        """
        Build script of API Hooking from Android APIs

        Parameters
        ----------
        apk_sha : str
            sha256 of the apk to hook

        Returns
        ------- 
        str  
            package name of the apk to hook
        """

        apis, pkg_name = self._parse_apk(apk_path)
        apk_sha = self._get_apk_sha(apk_path)
        self._build_script(apis, apk_sha)
        return pkg_name


    def _attach(self, apk_path: str, idx: int, pid: str) -> Tuple[int, str]:
        """
        attach to frida server to hook APIs based on the script

        Parameters
        ----------
        apk_path : str
            path of the apk to hook
        idx : int
            index of the frida run
        pid : str
            process id of the running apk

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

        cmd: List[str] = [
            self.frida_path,
            "-D",
            self.device,
            "-l",
            self.script,
            "-p",
            pid,
            ">",
            output_path
        ]

        process = subprocess.Popen(cmd, stderr=subprocess.DEVNULL)
        self.log.info(f"frida is attached and hooking APIs for {apk_path}")
        return process.pid

    def run_hooking(self, apk_path: str, pkg_name: str, max: int) -> None:
        """
        run hooking of the APIs

        Parameters
        ----------
        apk_path : str
            path of the apk to hook
        pkg_name : str
            package
        max : int
            max number of frida attachments
        """

        i = 0
        pid = self.adb.get_pid(pkg_name)
        while not pid and i < 2:
            sleep(20)
            pid =  self.adb.get_pid(pkg_name)
            i += 1
        
        if pid is not None:
            
            pid_frida = self._attach(apk_path, 0, pid)

            # Loop to handle frida re-attachment in case droidbot stops the application
            i = 0
            while True:
                try:
                    if psutil.Process(pid_frida).is_running():
                        continue
                    else:
                        i += 1
                        sleep(30)
                        pid = self.adb.get_pid(pkg_name)
                        if pid is not None:
                            pid_frida = self._attach(apk_path, i, pid)
                        else:
                            continue
                    if i == max:
                        break
                except psutil.NoSuchProcess:
                    if i < max:
                        continue
                    else:
                        break


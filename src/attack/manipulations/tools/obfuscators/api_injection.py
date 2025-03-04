"""
Custom implementation of API injection obfuscation technique for
the Obfuscapk tool.
"""

import logging

from obfuscapk import obfuscator_category, util
from src.attack.manipulations.manipulator import ManipulationStatus

from .util import generate_random_name


class ApiInjection(obfuscator_category.ICodeObfuscator):
    """Implementation of API injection obfuscation technique."""

    def __init__(self) -> None:
        """Create and inizialize and ApiInjection object."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        super().__init__()

    def obfuscate(self, obfuscation_info: ManipulationStatus) -> None:
        """
        Obfuscate the smali files by injecting the provided APIs.

        Parameters
        ----------
        obfuscation_info : ManipulationStatus
            The information about the current obfuscation process.
        """
        if not obfuscation_info.apis_to_inject:
            return

        self.logger.info('Running "%s" obfuscator', self.__class__.__name__)
        self.obfuscation_status = obfuscation_info

        try:
            # There is a method call limit for dex files
            max_methods_to_add = obfuscation_info.get_remaining_methods_per_obfuscator()
            if obfuscation_info.is_multidex():
                for index, dex_smali_files in enumerate(
                    util.show_list_progress(
                        obfuscation_info.get_multidex_smali_files(),
                        interactive=obfuscation_info.interactive,
                        unit="dex",
                        description="Processing multidex",
                    )
                ):
                    max_methods_to_add = (
                        obfuscation_info.get_remaining_methods_per_obfuscator()[index]
                    )
                    if self.treat_dex(
                        dex_smali_files,
                        max_methods_to_add,
                        obfuscation_info.interactive,
                    ):
                        break
            else:
                self.treat_dex(
                    obfuscation_info.get_smali_files(),
                    max_methods_to_add,
                    obfuscation_info.interactive,
                )
        except Exception as _:
            self.logger.exception(
                'Error during execution of "%s" obfuscator', self.__class__.__name__
            )
            raise
        finally:
            obfuscation_info.used_obfuscators.append(self.__class__.__name__)

    def treat_dex(
        self, smali_files: list[str], max_methods_to_add: int, interactive: bool
    ) -> bool:
        """
        Add the function that injects the APIs in the smali files.

        Parameters
        ----------
        smali_files : list[str]
            List of smali files to obfuscate.
        max_methods_to_add : int
            The maximum number of methods to add.
        interactive : bool
            Whether the obfuscation is interactive or not.

        Returns
        -------
        bool
            True if the function was added successfully, False otherwise.
        """
        added_methods = 0

        for smali_file in util.show_list_progress(
            smali_files,
            interactive=interactive,
            description="Inserting string injection function in smali files",
        ):
            if added_methods < max_methods_to_add and self.add_function(smali_file):
                added_methods += 1
                return True

        return False

    def add_function(self, smali_file: str) -> bool:
        """
        Add the static method that injects the APIs in the smali file.

        Parameters
        ----------
        smali_file : str
            The path to the smali file where the function will be added.

        Returns
        -------
        bool
            True if the function was added successfully, False otherwise.
        """
        apis = list(self.obfuscation_status.apis_to_inject)
        # Random name generation for the function
        function_name = generate_random_name()
        # String injection definition
        api_inj = __class__.api_injection(apis)
        # Method definition
        function_definition = (
            f".method public static {function_name}()V\n"
            "\t.registers 3\n"
            "\tconst/4 v0, 0x1\n"
            "\t.line 1\n"
            "\t.prologue\n"
            # impossible if since v0 = 1 is always != 0
            # so the :impossible label will be always reached
            "\tif-nez v0, :impossible\n"
            f"{api_inj}\n"
            "\t:impossible\n"
            "\treturn-void\n"
            ".end method\n"
        )

        flag = False
        with util.inplace_edit_file(smali_file) as (input_file, output_file):
            # inserting the static method inside the smali file after
            # # direct methods comment
            for line in input_file:
                if "# direct methods" in line:
                    output_file.write(line)
                    output_file.write(function_definition)
                    flag = True
                else:
                    output_file.write(line)

        return flag

    @staticmethod
    def api_injection(apis: list[str]) -> str:
        """
        Inject the provided list of APIs in the smali file.

        Parameters
        ----------
        apis : list[str]
            List of APIs to inject in the smali file.

        Returns
        -------
        str
            The string that contains the injection of the APIs in the smali file.
        """
        injection = ""
        for api in apis:
            if "<init>" in api:
                injection += (
                    "\tnew-instance v1, {};\n\tinvoke-direct {{v1}}, {}\n"
                ).format(api.split(";")[0], api)
            else:
                injection += (
                    "\tnew-instance v1, {};\n"
                    "\tinvoke-direct {{v1}}, {};-><init>()V\n"
                    "\tinvoke-virtual {{v1}}, {}\n"
                ).format(api.split(";")[0], api.split(";")[0], api)

        return injection

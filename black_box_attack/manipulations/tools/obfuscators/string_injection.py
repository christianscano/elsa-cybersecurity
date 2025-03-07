"""
Custom implementation of the string injection obfuscation technique
for the Obfuscapk tool.
"""

import logging

from obfuscapk import obfuscator_category, util

from ...manipulation_status import ManipulationStatus
from .util import generate_random_name


class StringInjection(obfuscator_category.ICodeObfuscator):
    """Implementation of string injection obfuscation technique."""

    def __init__(self) -> None:
        """Create and inizialize and StringInjection object."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        super().__init__()

    def obfuscate(self, obfuscation_info: ManipulationStatus) -> None:
        """
        Obfuscate the smali files by injecting the provided strings.

        Parameters
        ----------
        obfuscation_info : Manipulation
            Information about the obfuscation process
        """
        if not obfuscation_info.urls_to_inject:
            return

        self.logger.info('Running "%s" obfuscator', self.__class__.__name__)
        self.obfuscation_status = obfuscation_info

        try:
            # there is a method call limit for dex files
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
                    self.treat_dex(
                        dex_smali_files,
                        max_methods_to_add,
                        obfuscation_info.interactive,
                    )
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
        Control the number of methods to add to the dex file.

        Parameters
        ----------
        smali_files : list[str]
            list of smali file to modify
        max_methods_to_add : int
            max number of methods to add to the dex
        interactive : bool
            default is False

        Returns
        -------
        bool
            True if the function with the injected strings is added. False, otherwise.
        """
        strings = list(self.obfuscation_status.urls_to_inject)
        strings_to_inject = [strings[i : i + 15] for i in range(0, len(strings), 15)]
        added_methods = 0

        for smali_file in util.show_list_progress(
            smali_files,
            interactive=interactive,
            description="Inserting string injection function in smali files",
        ):
            if added_methods >= len(strings_to_inject):
                break
            if added_methods < max_methods_to_add:
                if self.add_function(smali_file, strings_to_inject[added_methods]):
                    added_methods += 1
                else:
                    continue
            else:
                return False

        return True

    def add_function(self, smali_file: str, strings: list[str]) -> None:
        """
        Add the function to the smali file.

        Parameters
        ----------
        smali_file : str
            smali file path to modify
        strings : list[str]
            list of strings to inject

        Returns
        -------
        bool
            True if the function with the injected strings is added. False, otherwise.
        """
        # Random name generation for the function
        function_name = generate_random_name()
        # String injection definition
        string_inj = self.string_injection(strings)
        # Method definition
        function_definition = (
            f".method public static {function_name}()V\n"
            f"\t.registers {len(strings)}\n"
            "\t.line 1\n"
            "\t.prologue\n"
            f"{string_inj}\n"
            "\treturn-void\n"
            ".end method\n"
        )

        flag = False
        with util.inplace_edit_file(smali_file) as (input_file, output_file):
            # inserting the static method inside the smali file after
            # the # direct methods comment
            for line in input_file:
                if "# direct methods" in line:
                    output_file.write(line)
                    output_file.write(function_definition)
                    flag = True
                else:
                    output_file.write(line)

        return flag

    @staticmethod
    def string_injection(urls: list[str]) -> str:
        """
        Generate the instructions to inject.

        Parameters
        ----------
        urls : list[str]
            List of strings to inject

        Returns
        -------
        str
            Instructions to inject in the smali
        """
        string_inj = ""

        for i, s in enumerate(urls):
            string_inj += f'\tconst-string v{i}, "{s}"\n'

        return string_inj

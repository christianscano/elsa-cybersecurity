"""
Custom implementation of the constant string encryption obfuscation technique
for the Obfuscapk tool.
"""

import re
from pathlib import Path

from obfuscapk import util
from obfuscapk.obfuscators.const_string_encryption import ConstStringEncryption
from src.attack.manipulations.manipulation_status import ManipulationStatus

from .util import read_smali_file, write_smali_file


class AttConstStringEncryption(ConstStringEncryption):
    """Implementation of the constant string encryption obfuscation technique."""

    def obfuscate(self, obfuscation_info: ManipulationStatus) -> None:
        """
        Obfuscate the constant strings in the smali files of the application.

        Parameters
        ----------
        obfuscation_info : ManipulationStatus
            Information about the obfuscation process.
        """
        if not obfuscation_info.string_to_encrypt:
            return

        self.logger.info('Running "%s" obfuscator', self.__class__.__name__)

        self.encryption_secret = obfuscation_info.encryption_secret
        try:
            encrypted_strings: set[str] = set()

            static_string_pattern = re.compile(
                r"\.field.+?static.+?(?P<string_name>\S+?):"
                r'Ljava/lang/String;\s=\s"(?P<string_value>.+)"',
                re.UNICODE,
            )

            for smali_file in util.show_list_progress(
                obfuscation_info.get_smali_files(),
                interactive=obfuscation_info.interactive,
                description="Encrypting constant strings",
            ):
                self.logger.debug(
                    'Encrypting constant strings in file "%s"', smali_file
                )

                lines = read_smali_file(smali_file)
                (
                    class_name,
                    static_string_index,
                    static_string_name,
                    static_string_value,
                    direct_methods_line,
                    static_constructor_line,
                    string_index,
                    string_register,
                    string_value,
                ) = self._extract_strings(
                    lines, obfuscation_info, static_string_pattern
                )

                self._encrypt_const_strings(
                    lines,
                    string_index,
                    string_register,
                    string_value,
                    encrypted_strings,
                )
                static_string_encryption_code = (
                    self._generate_static_string_encryption_code(
                        static_string_index,
                        static_string_name,
                        static_string_value,
                        class_name,
                        encrypted_strings,
                    )
                )

                self._update_static_constructor(
                    lines,
                    static_string_encryption_code,
                    static_constructor_line,
                    direct_methods_line,
                )

                write_smali_file(smali_file, lines)

            self._add_decrypt_string_smali_file(obfuscation_info, encrypted_strings)

        except Exception as _:
            self.logger.exception(
                'Error during execution of "%s" obfuscator', self.__class__.__name__
            )
            raise

        finally:
            obfuscation_info.used_obfuscators.append(self.__class__.__name__)

    def _extract_strings(
        self,
        lines: list[str],
        obfuscation_info: ManipulationStatus,
        static_string_pattern: re.Pattern,
    ) -> tuple:
        class_name = None
        static_string_index: list[int] = []
        static_string_name: list[str] = []
        static_string_value: list[str] = []
        direct_methods_line = -1
        static_constructor_line = -1
        string_index: list[int] = []
        string_register: list[str] = []
        string_value: list[str] = []
        current_local_count = 0

        for line_number, line in enumerate(lines):
            if not class_name:
                class_match = util.class_pattern.match(line)
                if class_match:
                    class_name = class_match.group("class_name")
                    continue

            if line.startswith("# direct methods"):
                direct_methods_line = line_number
                continue

            if line.startswith(".method") and line.strip().endswith(
                "static constructor <clinit>()V"
            ):
                static_constructor_line = line_number
                continue

            static_string_match = static_string_pattern.match(line)
            if (
                static_string_match
                and static_string_match.group("string_value")
                and static_string_match.group("string_value")
                in obfuscation_info.string_to_encrypt
            ):
                static_string_index.append(line_number)
                static_string_name.append(static_string_match.group("string_name"))
                static_string_value.append(static_string_match.group("string_value"))

            match = util.locals_pattern.match(line)
            if match:
                current_local_count = int(match.group("local_count"))
                continue

            string_match = util.const_string_pattern.match(line)
            if (
                string_match
                and string_match.group("string")
                and string_match.group("string") in obfuscation_info.string_to_encrypt
            ):
                reg_type = string_match.group("register")[:1]
                reg_number = int(string_match.group("register")[1:])
                if (reg_type == "v" and reg_number <= 15) or (
                    reg_type == "p" and reg_number + current_local_count <= 15
                ):
                    string_index.append(line_number)
                    string_register.append(string_match.group("register"))
                    string_value.append(string_match.group("string"))

        return (
            class_name,
            static_string_index,
            static_string_name,
            static_string_value,
            direct_methods_line,
            static_constructor_line,
            string_index,
            string_register,
            string_value,
        )

    def _encrypt_const_strings(
        self,
        lines: list[str],
        string_index: list[int],
        string_register: list[str],
        string_value: list[str],
        encrypted_strings: set[str],
    ) -> None:
        for string_number, index in enumerate(string_index):
            lines[index] = (
                f"\tconst-string/jumbo {string_register[string_number]}, "
                f'"{self.encrypt_string(string_value[string_number])}"\n'
                f"\n\tinvoke-static {{{string_register[string_number]}}}, "
                "Lcom/decryptstringmanager/DecryptString"
                ";->decryptString(Ljava/lang/String;)Ljava/lang/String;\n"
                f"\n\tmove-result-object {string_register[string_number]}\n"
            )
            encrypted_strings.add(string_value[string_number])

    def _generate_static_string_encryption_code(
        self,
        static_string_index: list[int],
        static_string_name: list[str],
        static_string_value: list[str],
        class_name: str,
        encrypted_strings: set[str],
    ) -> str:
        static_string_encryption_code = ""
        for string_number, _index in enumerate(static_string_index):
            static_string_encryption_code += (
                f'\tconst-string/jumbo v0, "'
                f'{self.encrypt_string(static_string_value[string_number])}"\n'
                "\n\tinvoke-static {{v0}}, "
                "Lcom/decryptstringmanager/DecryptString"
                ";->decryptString(Ljava/lang/String;)Ljava/lang/String;\n"
                "\n\tmove-result-object v0\n"
                f"\n\tsput-object v0, {class_name}->"
                f"{static_string_name[string_number]}:Ljava/lang/String;\n\n"
            )
            encrypted_strings.add(static_string_value[string_number])

        return static_string_encryption_code

    def _update_static_constructor(
        self,
        lines: list[str],
        static_string_encryption_code: str,
        static_constructor_line: int,
        direct_methods_line: int,
    ) -> None:
        if static_string_encryption_code != "":
            if static_constructor_line != -1:
                local_match = util.locals_pattern.match(
                    lines[static_constructor_line + 1]
                )

                if local_match:
                    local_count = int(local_match.group("local_count"))
                    if local_count == 0:
                        lines[static_constructor_line + 1] = "\t.locals 1\n"
                    lines[static_constructor_line + 2] = (
                        f"\n{static_string_encryption_code}"
                    )
            else:
                if direct_methods_line != -1:
                    new_constructor_line = direct_methods_line
                else:
                    new_constructor_line = len(lines) - 1
                lines[new_constructor_line] = (
                    f"{lines[new_constructor_line]}"
                    ".method static constructor <clinit>()V\n"
                    "\t.locals 1\n\n"
                    "{static_string_encryption_code}"
                    "\treturn-void\n"
                    ".end method\n\n"
                )

    def _add_decrypt_string_smali_file(
        self, obfuscation_info: ManipulationStatus, encrypted_strings: set[str]
    ) -> None:
        if (
            not obfuscation_info.decrypt_string_smali_file_added_flag
            and encrypted_strings
        ):
            destination_dir = Path(obfuscation_info.get_smali_files()[0]).parent
            destination_file = Path(destination_dir) / "DecryptString.smali"
            with Path(destination_file).open(
                "w", encoding="utf-8"
            ) as decrypt_string_smali:
                decrypt_string_smali.write(
                    util.get_decrypt_string_smali_code(self.encryption_secret)
                )
                obfuscation_info.decrypt_string_smali_file_added_flag = True

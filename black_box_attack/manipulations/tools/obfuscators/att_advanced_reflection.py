"""
Custom implementation of AdvancedReflection obfuscation technique for
the Obfuscapk tool.
"""

import re
from pathlib import Path

from obfuscapk import util
from obfuscapk.obfuscators.advanced_reflection import AdvancedReflection

from ...manipulation_status import ManipulationStatus
from .util import read_smali_file, write_smali_file


class AttAdvancedReflection(AdvancedReflection):
    """Implementation of the AdvancedReflection obfuscation technique."""

    def obfuscate(self, obfuscation_info: ManipulationStatus) -> None:
        """
        Obfuscate the smali files by using reflection to call dangerous APIs.

        Parameters
        ----------
        obfuscation_info : ManipulationStatus
            The information about the obfuscation process.
        """
        if not obfuscation_info.android_api_to_reflect:
            return

        self.logger.info('Running "%s" obfuscator', self.__class__.__name__)

        try:
            obfuscator_smali_code: str = ""
            move_result_pattern = re.compile(
                r"\s+move-result.*?\s(?P<register>[vp0-9]+)"
            )

            for smali_file in util.show_list_progress(
                obfuscation_info.get_smali_files(),
                interactive=obfuscation_info.interactive,
                description="Obfuscating dangerous APIs using reflection",
            ):
                self.logger.debug(
                    'Obfuscating dangerous APIs using reflection in file "%s"',
                    smali_file,
                )

                # There is no space for further reflection instructions.
                if (
                    self.obfuscator_instructions_length
                    >= self.obfuscator_instructions_limit
                ):
                    break

                lines = read_smali_file(smali_file)
                method_index, method_is_reflectable, method_local_count = (
                    self._analyze_methods(lines)
                )

                self._process_methods(
                    lines,
                    method_index,
                    method_is_reflectable,
                    method_local_count,
                    obfuscation_info,
                    move_result_pattern,
                    obfuscator_smali_code,
                )

                write_smali_file(smali_file, lines)

            self._add_reflection_code_to_app(obfuscation_info, obfuscator_smali_code)

        except Exception as _:
            self.logger.exception(
                'Error during execution of "%s" obfuscator', self.__class__.__name__
            )
            raise

        finally:
            obfuscation_info.used_obfuscators.append(self.__class__.__name__)

    def _analyze_methods(
        self, lines: list[str]
    ) -> tuple[list[int], list[bool], list[int]]:
        """
        Analyze the methods in the smali file.

        Parameters
        ----------
        lines : list[str]
            The content of the smali file.

        Returns
        -------
        tuple[list[int], list[bool], list[int]]
            The indexes of the methods, the reflectability of the methods,
            and the local count of the
        """
        # Line numbers where a method is declared.
        method_index: list[int] = []
        # For each method in method_index, True if there are enough registers
        # to perform some operations by using reflection, False otherwise.
        method_is_reflectable: list[bool] = []
        # The number of local registers of each method in method_index.
        method_local_count: list[int] = []

        # Find the method declarations in this smali file.
        for line_number, line in enumerate(lines):
            method_match = util.method_pattern.match(line)
            if method_match:
                method_index.append(line_number)

                param_count = self.count_needed_registers(
                    self.split_method_params(method_match.group("method_param"))
                )

                # Save the number of local registers of this method.
                local_count = 16
                local_match = util.locals_pattern.match(lines[line_number + 1])
                if local_match:
                    local_count = int(local_match.group("local_count"))

                method_local_count.append(local_count)

                # If there are enough registers available we can perform some
                # reflection operations.
                if param_count + local_count <= 11:
                    method_is_reflectable.append(True)
                else:
                    method_is_reflectable.append(False)

        return method_index, method_is_reflectable, method_local_count

    def _process_methods(
        self,
        lines: list[str],
        method_index: list[int],
        method_is_reflectable: list[bool],
        method_local_count: list[int],
        obfuscation_info: ManipulationStatus,
        move_result_pattern: re.Pattern,
        obfuscator_smali_code: str,
    ) -> None:
        """
        Process the methods in the smali file, looking for method invocations
        of dangerous APIs inside the methods declared in this smali file and
        change normal invocations with invocations through reflection.

        Parameters
        ----------
        lines : list[str]
            The content of the smali file.
        method_index : list[int]
            The indexes of the methods.
        method_is_reflectable : list[bool]
            The reflectability of the methods.
        method_local_count : list[int]
            The local count of the methods.
        obfuscation_info : ManipulationStatus
            The information about the obfuscation process.
        move_result_pattern : re.Pattern
            The pattern to match the move result.
        obfuscator_smali_code : str
            The smali code to add to the obfuscator.
        """
        for method_number, index in enumerate(method_index):
            # If there are enough registers for reflection operations, look for
            # method invocations inside each method's body.
            if method_is_reflectable[method_number]:
                current_line_number = index

                while not lines[current_line_number].startswith(".end method"):
                    # There is no space for further reflection instructions.
                    if (
                        self.obfuscator_instructions_length
                        >= self.obfuscator_instructions_limit
                    ):
                        break

                    current_line_number += 1

                    invoke_match = util.invoke_pattern.match(lines[current_line_number])
                    if invoke_match:
                        method = (
                            "{class_name}->{method_name}"
                            "({method_param}){method_return}".format(
                                class_name=invoke_match.group("invoke_object"),
                                method_name=invoke_match.group("invoke_method"),
                                method_param=invoke_match.group("invoke_param"),
                                method_return=invoke_match.group("invoke_return"),
                            )
                        )

                        # Use reflection only if this method belongs to dangerous APIs.
                        if method not in obfuscation_info.android_api_to_reflect:
                            continue

                        tmp_is_virtual = (
                            invoke_match.group("invoke_type") == "invoke-virtual"
                        )
                        tmp_register = invoke_match.group("invoke_pass")
                        tmp_class_name = invoke_match.group("invoke_object")
                        tmp_method = invoke_match.group("invoke_method")
                        tmp_param = invoke_match.group("invoke_param")
                        tmp_return_type = invoke_match.group("invoke_return")

                        self._handle_move_result(
                            lines,
                            current_line_number,
                            move_result_pattern,
                            tmp_return_type,
                        )

                        obfuscator_smali_code += self.add_smali_reflection_code(
                            tmp_class_name, tmp_method, tmp_param
                        )

                        lines[current_line_number] = self.create_reflection_method(
                            self.methods_with_reflection,
                            method_local_count[method_number],
                            tmp_is_virtual,
                            tmp_register,
                            tmp_param,
                        )

                        self.methods_with_reflection += 1

                        lines[index + 1] = (
                            f"\t.locals {method_local_count[method_number] + 4}\n"
                        )

    def _handle_move_result(
        self,
        lines: list[str],
        current_line_number: int,
        move_result_pattern: re.Pattern,
        tmp_return_type: str,
    ) -> None:
        """
        Check if the method invocation result is used in the following lines.

        Parameters
        ----------
        lines : list[str]
            The content of the smali file.
        current_line_number : int
            The current line number.
        move_result_pattern : re.Pattern
            The pattern to match the move result.
        tmp_return_type : str
            The return type of the method
        """
        for move_result_index in range(
            current_line_number + 1, min(current_line_number + 10, len(lines) - 1)
        ):
            if "invoke-" in lines[move_result_index]:
                break

            move_result_match = move_result_pattern.match(lines[move_result_index])
            if move_result_match:
                tmp_result_register = move_result_match.group("register")

                new_move_result = ""
                if tmp_return_type in self.primitive_types:
                    new_move_result += (
                        "\tmove-result-object "
                        f"{tmp_result_register}\n\n"
                        f"\tcheck-cast {tmp_result_register}, "
                        f"{self.type_dict[tmp_return_type]}\n\n"
                    )

                    new_move_result += (
                        f"\tinvoke-virtual {{{tmp_result_register}}}, "
                        f"{self.reverse_cast_dict[tmp_return_type]}\n\n"
                    )

                    if tmp_return_type in {"J", "D"}:
                        new_move_result += f"\tmove-result-wide {tmp_result_register}\n"
                    else:
                        new_move_result += f"\tmove-result {tmp_result_register}\n"

                else:
                    new_move_result += (
                        "\tmove-result-object "
                        f"{tmp_result_register}\n\n"
                        f"\tcheck-cast {tmp_result_register}, "
                        f"{tmp_return_type}\n"
                    )

                lines[move_result_index] = new_move_result

    def _add_reflection_code_to_app(
        self, obfuscation_info: ManipulationStatus, obfuscator_smali_code: str
    ) -> None:
        """
        Add the code needed for the reflection obfuscato to the app. The code
        can be put in any smali directory, since it will be moved to the correct
        directory when rebuilding the application.

        Parameters
        ----------
        obfuscation_info : ManipulationStatus
            The information about the obfuscation process.
        obfuscator_smali_code : str
            The smali code to add to the obfuscator.
        """
        destination_dir = Path(obfuscation_info.get_smali_files()[0]).parent
        destination_file = Path(destination_dir) / "AdvancedApiReflection.smali"

        with destination_file.open("w", encoding="utf-8") as api_reflection_smali:
            reflection_code = util.get_advanced_api_reflection_smali_code().replace(
                "#!code_to_replace!#", obfuscator_smali_code
            )
            api_reflection_smali.write(reflection_code)

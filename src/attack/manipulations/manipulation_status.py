"""
The module provides the `ManipulationStatus` class, which is used to manage the
APK during the manipulation process. It includes methods for decompiling,
recompiling, and updating the APK, as well as tracking the changes made during
the manipulation process.
"""

import os
from pathlib import Path
from shutil import copytree, rmtree
from typing import Optional

from memory_tempfile import MemoryTempfile
from obfuscapk import util
from obfuscapk.obfuscation import Obfuscation
from obfuscapk.toolbundledecompiler import BundleDecompiler

from .tools.apktool import Apktool


class ManipulationStatus(Obfuscation):
    """
    Class contains the references to the APK, the methods for
    decompiling/recompiling it, and the status of the changes to be made.
    A single object is passed from the attack to the various obfuscators.
    """

    def __init__(
        self,
        apk_path: str,
        obfuscated_apk_path: Optional[str] = None,
        ignore_libs: bool = False,
        interactive: bool = False,
        virus_total_api_key: Optional[str] = None,
        keystore_file: Optional[str] = None,
        keystore_password: Optional[str] = None,
        key_alias: Optional[str] = None,
        key_password: Optional[str] = None,
        ignore_packages_file: Optional[str] = None,
        use_aapt2: bool = False,
    ) -> None:
        """
        Create and initialize the ManipulationStatus object.

        Parameters
        ----------
        apk_path : str
            The path to the APK file to obfuscate.
        obfuscated_apk_path : str, optional
            The path to the obfuscated APK file.
        ignore_libs : bool, optional
            If True, the third-party libraries are ignored.
        interactive : bool, optional
            If True, the obfuscation process is interactive.
        virus_total_api_key : str, optional
            The VirusTotal API key.
        keystore_file : str, optional
            The path to the keystore file.
        keystore_password : str, optional
            The password of the keystore file.
        key_alias : str, optional
            The alias of the key.
        key_password : str, optional
            The password of the key.
        ignore_packages_file : str, optional
            The path to the file containing the list of packages to ignore.
        use_aapt2 : bool, optional
            If True, the aapt2 tool is used.
        """
        working_dir_path = MemoryTempfile().gettempdir()

        super(__class__, self).__init__(
            apk_path,
            working_dir_path,
            obfuscated_apk_path,
            ignore_libs,
            interactive,
            virus_total_api_key,
            keystore_file,
            keystore_password,
            key_alias,
            key_password,
            ignore_packages_file,
            use_aapt2,
        )

        self._string_to_encrypt = set()
        self._api_to_reflect = set()
        self._android_api_to_reflect = set()
        self._n_arithmetic_branch = 0
        self._class_to_rename = set()
        self._call_to_redirect = set()
        self._urls_to_inject = set()
        self._apis_to_inject = set()
        self._orig_decoded_apk_path = None
        self._dir_list = set()
        self._multidex_smali_files = []
        self._is_decoded = False

    def update_path(self, idx: int) -> None:
        """
        Update the decoded APK path to the new one.

        Parameters
        ----------
        idx : int
            The index of the manipulation.
        """
        new_decoded_apk_path = self._orig_decoded_apk_path + f"_manip_{idx}"
        self._handle_existing_path(new_decoded_apk_path)
        self._copy_and_link_assets(new_decoded_apk_path)
        self._update_internal_paths(new_decoded_apk_path)
        self._smali_files = self._get_smali_files()
        self._check_multidex()
        self._update_native_lib_files()

    def decode_apk(
        self,
        skip_resources: bool = False,
        skip_code: bool = False,
        only_main_dex: bool = False,
    ) -> None:
        """
        Decode the APK file using apktool or BundleDecompiler.

        Parameters
        ----------
        skip_resources : bool
            If True, the resources are not decoded.
        skip_code : bool
            If True, the code is not decoded.
        only_main_dex : bool
            If True, only the main dex is decoded.
        """
        if not self._is_decoded:
            # The input apk will be decoded with apktool or BundleDecompiler.
            apktool: Apktool = Apktool()
            bundledecompiler: BundleDecompiler = BundleDecompiler()

            # <working_directory>/<apk_path>/
            self._decoded_apk_path = str(
                Path(self.working_dir_path) / Path(self.apk_path).stem
            )
            self._dir_list.add(self._decoded_apk_path)

            try:
                if self.is_bundle:
                    bundledecompiler.decode(
                        self.apk_path, self._decoded_apk_path, force=False
                    )
                else:
                    apktool.decode(
                        self.apk_path,
                        self._decoded_apk_path,
                        force=True,
                        skip_resources=skip_resources,
                        skip_code=skip_code,
                        only_main_dex=only_main_dex,
                    )

                # Update manifest file path.
                self._manifest_file = self._get_manifest_file(self._decoded_apk_path)

                # Setup smali files, multidex status and native libraries.
                self._smali_files = self._get_smali_files()
                self._check_multidex()
                self._update_native_lib_files()

            except Exception as _:
                self.logger.exception("Error during apk decoding")
                raise
            else:
                self._is_decoded = True

        self._orig_decoded_apk_path = self._decoded_apk_path

    def clean_iter(self, idx: int) -> None:
        """Clean the directories of the manipulated APKs."""
        decoded_apk_path = self._orig_decoded_apk_path + f"_manip_{idx}"
        if Path(decoded_apk_path).exists():
            rmtree(decoded_apk_path)

    def clean_data(self) -> None:
        """Clean the data directories."""
        for data_dir in self._dir_list:
            if Path(data_dir).exists():
                rmtree(data_dir)

    def reset(self) -> None:
        """Reset the ManipulationStatus object."""
        self.class_to_rename = set()
        self.android_api_to_reflect = set()
        self.string_to_encrypt = set()
        self.urls_to_inject = set()
        self.apis_to_inject = set()
        self.obfuscators_adding_fields = 0
        self.obfuscators_adding_methods = 0
        self.decrypt_asset_smali_file_added_flag = False
        self.decrypt_string_smali_file_added_flag = False

    # ------------------
    # Private functions
    # ------------------

    def _handle_existing_path(self, new_decoded_apk_path: str) -> None:
        if Path(new_decoded_apk_path).exists():
            rmtree(new_decoded_apk_path)
            if new_decoded_apk_path in self._dir_list:
                self._dir_list.remove(new_decoded_apk_path)

    def _copy_and_link_assets(self, new_decoded_apk_path: str) -> None:
        copytree(
            self._orig_decoded_apk_path,
            new_decoded_apk_path,
            ignore=lambda directory, _contents: ["assets"]
            if directory == self._orig_decoded_apk_path
            else [],
        )
        if (Path(self._orig_decoded_apk_path) / "assets").is_dir():
            os.symlink(
                Path(self._orig_decoded_apk_path) / "assets",
                Path(new_decoded_apk_path) / "assets",
            )

    def _update_internal_paths(self, new_decoded_apk_path: str) -> None:
        self._decoded_apk_path = new_decoded_apk_path
        self._dir_list.add(self._decoded_apk_path)
        self._manifest_file = self._get_manifest_file(self._decoded_apk_path)

    def _get_manifest_file(self, decoded_apk_path: str) -> Path:
        return (
            Path(decoded_apk_path) / "base" / "manifest" / "AndroidManifest.xml"
            if self.is_bundle
            else Path(decoded_apk_path) / "AndroidManifest.xml"
        )

    def _get_smali_files(self) -> list:
        """Retrieve and filter the list of smali files."""
        smali_files = [
            Path(root) / file_name
            for root, _dir_names, file_names in os.walk(self._decoded_apk_path)
            for file_name in file_names
            if file_name.endswith(".smali")
        ]

        if self.ignore_libs:
            libs_to_ignore = [
                Path(os.path.normpath(x)) / "" for x in util.get_libs_to_ignore()
            ]

            filtered_smali_files = []
            for smali_file in smali_files:
                relative_smali_file = Path(
                    *os.path.relpath(smali_file, self._decoded_apk_path).split(
                        os.path.sep
                    )[1:]
                )
                if not any(
                    str(relative_smali_file).startswith(str(lib))
                    for lib in libs_to_ignore
                ):
                    filtered_smali_files.append(smali_file)
            smali_files = filtered_smali_files

        smali_files.sort()

        return smali_files

    def _check_multidex(self) -> None:
        """Check if the APK is multidex and organize smali files accordingly."""
        self._is_multidex = False
        self._multidex_smali_files = []
        base_path = Path(self._decoded_apk_path)

        if self.is_bundle:
            if (base_path / "base" / "dex" / "smali_classes2").is_dir():
                self._is_multidex = True
        elif (base_path / "smali_classes2").is_dir():
            self._is_multidex = True

        if self._is_multidex:
            smali_directories = ["smali"] + [f"smali_classes{i}" for i in range(2, 15)]
            for smali_directory in smali_directories:
                current_directory = (
                    base_path / "base" / "dex" / smali_directory
                    if self.is_bundle
                    else base_path / smali_directory
                )

                if current_directory.is_dir():
                    multidex_files = [
                        smali_file
                        for smali_file in self._smali_files
                        if str(smali_file).startswith(str(current_directory))
                    ]
                    self._multidex_smali_files.append(multidex_files)

    def _update_native_lib_files(self) -> None:
        """Update the list of native library files (.so) included in the application."""
        self._native_lib_files = [
            Path(root) / file_name
            for root, _dir_names, file_names in os.walk(
                Path(self._decoded_apk_path) / "lib"
            )
            for file_name in file_names
            if file_name.endswith(".so")
        ]
        self._native_lib_files.sort()

    # ------------
    #  Properties
    # ------------

    @property
    def string_to_encrypt(self) -> set:
        """Return the set of strings to encrypt."""
        return self._string_to_encrypt

    @string_to_encrypt.setter
    def string_to_encrypt(self, value: set) -> None:
        self._string_to_encrypt = value

    @property
    def android_api_to_reflect(self) -> set:
        """Return the set of Android APIs to reflect."""
        return self._android_api_to_reflect

    @android_api_to_reflect.setter
    def android_api_to_reflect(self, value: set) -> None:
        self._android_api_to_reflect = value

    @property
    def class_to_rename(self) -> set:
        """Return the set of classes to rename."""
        return self._class_to_rename

    @class_to_rename.setter
    def class_to_rename(self, value: set) -> None:
        self._class_to_rename = value

    @property
    def urls_to_inject(self) -> set:
        """Return the set of URLs to inject."""
        return self._urls_to_inject

    @urls_to_inject.setter
    def urls_to_inject(self, value: set) -> None:
        self._urls_to_inject = value

    @property
    def apis_to_inject(self) -> set:
        """Return the set of APIs to inject."""
        return self._apis_to_inject

    @apis_to_inject.setter
    def apis_to_inject(self, value: set) -> None:
        self._apis_to_inject = value

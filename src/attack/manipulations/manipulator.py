import logging
import os
import uuid
from pathlib import Path

from obfuscapk.tool import ApkSigner, Apktool, Zipalign
from secml.parallel import parfor2

from .manipulation_space import Manipulations
from .manipulation_status import ManipulationStatus
from .manipulator import Manipulator
from .obfuscators import (
    ApiInjection,
    AttAdvancedReflection,
    AttClassRename,
    AttConstStringEncryption,
    StringInjection,
)

# For the plugin system log only the error messages and ignore the log level
# set by the user.
logging.getLogger("yapsy").level = logging.ERROR

path                                 = Path(__file__).parent / "lib"
os.environ["APKTOOL_PATH"]           = str(path / "apktool")
os.environ["APKSIGNER_PATH"]         = str(path / "apksigner")
os.environ["BUNDLE_DECOMPILER_PATH"] = str(path / "BundleDecompiler.jar")


def _apply_manipulations(
    idx               : int,
    manipulator       : Manipulator,
    manipulations_list: list[Manipulations]
) -> Manipulations:
    """"""
    manipulator.manipulation_status.obfuscated_apk_path = (
        manipulator.manipulated_apks_dir(
            f"{Path(manipulator._apk_path).stem}_"
            f"{uuid.uuid1().hex}.apk"
        )
    )

    manipulations = manipulations_list[idx]

    try:
        manipulator._manipulate(manipulations, idx)
        manipulator.manipulation_status.build_obfuscated_apk()
    except:
        manipulations = None
    finally:
        manipulator.manipulation_status.clean_iter(idx)
        if Path(manipulator.manipulation_status.obfuscated_apk_path).exists():
            Path(manipulator.manipulation_status.obfuscated_apk_path).unlink()

    return manipulations


class Manipulator:
    """Class for performing the APK manipulation."""

    def __init__(
        self,
        apk_path            : str,
        manipulated_apks_dir: str,
        logging_level       : int = logging.INFO
    ) -> None:
        """
        Create and inizialize the Manipulator object.

        Parameters
        ----------
        apk_path : str
            Path to the APK to manipulate
        manipulated_apks_dir : str
            Directory where to save the manipulated APKs
        logging_level : int
            Logging level
        """
        self._manipulated_apks_dir = manipulated_apks_dir

        # Logging configuration.
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(
            format="%(asctime)s> [%(levelname)s][%(name)s][%(funcName)s()] %(message)s",
            datefmt="%d/%m/%Y %H:%M:%S",
            level=logging_level,
        )

        self._check_external_tool_dependencies()
        self._apk_path = apk_path
        self._only_main_dex = False

        self.obfuscators = [
            AttClassRename(),
            AttAdvancedReflection(),
            AttConstStringEncryption(),
            ApiInjection(),
            StringInjection(),
        ]

        self.manipulation_status = ManipulationStatus(
            apk_path,
            obfuscated_apk_path        = None,
            is_decoded                 = False,
            is_signed                  = False,
            aligned_apk_path           = None,
            signed_apk_path            = None,
            aligned_signed_apk_path    = None,
            obfuscators_adding_fields  = None,
            obfuscators_adding_methods = None,
            urls_to_inject             = None,
            apis_to_inject             = None,
            string_to_encrypt          = None,
            android_api_to_reflect     = None,
            class_to_rename            = None,
            only_main_dex              = False
        )

        self._decode_apk()

    def manipulate(self, manipulations: Manipulations, i: int) -> str:
        """
        Perform the APK manipulation.

        Parameters
        ----------
        manipulations : Manipulations
            Manipulations to apply
        i : int
            Index of the manipulation

        Returns
        -------
        str
            Path to the manipulated APK
        """
        obfuscated_apk_path = self.manipulated_apks_dir(
            f"{Path(self._apk_path).stem}_"
            f"{uuid.uuid1().hex}.apk"
        )

        self.manipulation_status.obfuscated_apk_path = obfuscated_apk_path

        try:
            self._manipulate(manipulations, i)
            self.manipulation_status.build_obfuscated_apk()
            self.manipulation_status.sign_obfuscated_apk()
            self.manipulation_status.align_obfuscated_apk()
        except Exception as _:
            self.logger.exception("Error during APK manipulation")
            obfuscated_apk_path = None
        finally:
            self.manipulation_status.clean_iter(i)

        return obfuscated_apk_path

    def manipulated_apks_dir(self, file: str) -> str:
        """
        Build the path to the manipulated APK.

        Parameters
        ----------
        file : str
            File name of the manipulated APK

        Returns
        -------
        str
            Path to the manipulated APK
        """
        return Path(self._manipulated_apks_dir) / file

    def get_error_free_manipulations(
        self,
        manipulations: Manipulations,
        n_jobs: int = 1
    ) -> Manipulations:
        """"
        Retrieve all possible manipulations that do not raise any error
        in a specific APK.

        Parameters
        ----------
        manipulations : Manipulations
            Possible manipulations to apply
        n_jobs : int
            Number of jobs to run in parallel

        Returns
        -------
        Manipulations
            Manipulations that do not raise any error
        """
        self.logger.debug("Checking error-free manipulations")

        # Test a build without applying manipulations, if the
        # APK cannot be built, it retries without decompiling
        # resources and considering only main dex files.
        try:
            self.manipulation_status.build_obfuscated_apk()
        except Exception as _:
            self._clean_data()

            if Path(self.manipulation_status.obfuscated_apk_path).exists():
                Path(self.manipulation_status.obfuscated_apk_path).unlink()
            try:
                self.logger.debug(
                    "Error during APK building: trying"
                    "without decompiling resources"
                    "and considering only main dex files"
                )
                self.manipulation_status._is_decoded = False
                self.manipulation_status.decode_apk(
                    skip_resources = True,
                    only_main_dex  = self._only_main_dex
                )
                self.manipulation_status.build_obfuscated_apk()
                self.obfuscators = [
                    o for o in self.obfuscators if not isinstance(o, AttClassRename)
                ]
            except Exception as e:
                self._clean_data()
                self.logger.critical("The APK cannot be build: %s", e)
                raise
        finally:
            if Path(self.manipulation_status.obfuscated_apk_path).exists:
                Path(self.manipulation_status.obfuscated_apk_path).unlink()

        error_free_manipulations = Manipulations([], [])

        def _recurse_apply_manipulations(manipulations: Manipulations) -> None:
            if isinstance(manipulations, Manipulations):
                manipulations_list = [manipulations]
            else:
                manipulations_list = manipulations

            applied_manipulations_list = parfor2(
                _apply_manipulations,
                len(manipulations_list),
                n_jobs,
                self,
                manipulations_list,
            )

            for applied_manipulations, manipulations in zip(
                applied_manipulations_list, manipulations_list
            ):
                if applied_manipulations is None:
                    if len(manipulations) > 1:
                        n = min(n_jobs, len(manipulations))
                        idxs = manipulations.get_idxs()
                        manipulations = [
                            manipulations.get_manipulations_from_vector(idxs[i::n])
                            for i in range(n)
                        ]
                        _recurse_apply_manipulations(manipulations)
                else:
                    error_free_manipulations.inject.extend(applied_manipulations.inject)
                    error_free_manipulations.obfuscate.extend(
                        applied_manipulations.obfuscate
                    )

        _recurse_apply_manipulations(manipulations)

        return error_free_manipulations

    # ----------------
    # Private methods
    # ----------------

    def _check_external_tool_dependencies(self) -> None:
        """Make sure all the external needed tools are available and ready to be used."""
        # APKTOOL_PATH, APKSIGNER_PATH and ZIPALIGN_PATH environment variables can be
        # used to specify the location of the external tools (make sure they have the
        # execute permission). If there is a problem with any of the executables below,
        # an exception will be thrown by the corresponding constructor.
        self.logger.debug("Checking external tool dependencies")
        Apktool()
        ApkSigner()
        Zipalign()


    def _decode_apk(self) -> None:
        """Try to decode the APK."""
        self.logger.debug("Decoding APK")

        try:
            self.manipulation_status.decode_apk()
        except Exception as e:
            self._clean_data()

            if Path(self.manipulation_status.obfuscated_apk_path).exists():
                Path(self.manipulation_status.obfuscated_apk_path).unlink()

            try:
                self.logger.debug(
                    "Error while decoding APK: trying again"
                    "considering only main dex files"
                )
                self.manipulation_status.decode_apk(only_main_dex = True)
                self._only_main_dex = True
            except Exception as e:
                self._clean_data()
                if Path(self.manipulation_status.obfuscated_apk_path).exists():
                    Path(self.manipulation_status.obfuscated_apk_path).unlink()

                self.logger.critical(
                    "Error during APK decoding: %s", e, exc_info = True
                )

                raise

    def _manipulate(self, manipulations: Manipulations, idx: int) -> None:
        self.manipulation_status.reset()
        self.manipulation_status.update_path(idx)

        for feature in manipulations.inject:
            splitted_feat = feature.split("::")
            feat_type, feat = splitted_feat[0], splitted_feat[1]
            if feat_type == "urls":
                self.manipulation_status.urls_to_inject.add(feat)
            elif feat_type == "api_calls":
                self.manipulation_status.apis_to_inject.add(feat)

        for feature in manipulations.obfuscate:
            splitted_feat = feature.split("::")
            feat_type, feat = splitted_feat[0], splitted_feat[1]
            if feat_type == "urls":
                self.manipulation_status.string_to_encrypt.add(feat)
            elif feat_type in {"api_calls", "suspicious_calls"}:
                self.manipulation_status.android_api_to_reflect.add(feat)
            elif feat_type in ["activities", "services", "providers", "receivers"]:
                self.manipulation_status.class_to_rename.add(
                    "L" + feat.replace(".", "/") + ";"
                )

        for obfuscator in self.obfuscators:
            if obfuscator.is_adding_fields:
                self.manipulation_status.obfuscators_adding_fields += 1
            if obfuscator.is_adding_methods:
                self.manipulation_status.obfuscators_adding_methods += 1

        for obfuscator in self.obfuscators:
            obfuscator.obfuscate(self.manipulation_status)

    def _clean_data(self) -> None:
        """Clean the state of the ManipulationStatus object."""
        self.manipulation_status.clean_data()

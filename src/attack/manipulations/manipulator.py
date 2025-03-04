""" """

import logging
import os
import pickle
import uuid
from pathlib import Path
from typing import Optional

from models.base import BaseModel
from obfuscapk.tool import ApkSigner, Apktool, Zipalign
from secml.parallel import parfor2

from .manipulation_space import Manipulations, ManipulationSpace
from .manipulation_status import ManipulationStatus
from .tools.obfuscators import (
    ApiInjection,
    AttAdvancedReflection,
    AttClassRename,
    AttConstStringEncryption,
    StringInjection,
)

# For the plugin system log only the error messages and ignore the log level
# set by the user.
logging.getLogger("yapsy").level = logging.ERROR
logging.getLogger("obfuscapk.tool.Apktool").setLevel(logging.CRITICAL)
logging.getLogger("obfuscapk.obfuscation").setLevel(logging.CRITICAL)

path = Path(__file__).parent / "tools/lib"
os.environ["APKTOOL_PATH"] = str(path / "apktool")
os.environ["APKSIGNER_PATH"] = str(path / "apksigner")
os.environ["BUNDLE_DECOMPILER_PATH"] = str(path / "BundleDecompiler.jar")


class Manipulator:
    """Class for performing the APK manipulation."""

    def __init__(
        self,
        apk_path: str,
        manipulated_apks_dir: str,
        logging_level: int = logging.INFO,
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
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging_level)

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
            apk_path=apk_path,
            obfuscated_apk_path=None,
            ignore_libs=False,
            interactive=False,
            virus_total_api_key=None,
            keystore_file=None,
            keystore_password=None,
            key_alias=None,
            key_password=None,
            ignore_packages_file=None,
            use_aapt2=False,
        )

        self._decode_apk()

    def manipulate(self, manipulations: Manipulations, idx: int) -> str:
        """
        Perform the provided manipulations to the APK under analysis.

        Parameters
        ----------
        manipulations : Manipulations
            Possible manipulations to apply
        idx : int
            Index of the manipulation

        Returns
        -------
        str
            Path to the manipulated APK
        """
        obfuscated_apk_path = self.get_manipulated_apks_dir(
            f"{Path(self._apk_path).stem}_{uuid.uuid1().hex}.apk"
        )

        self.manipulation_status.obfuscated_apk_path = obfuscated_apk_path

        try:
            self._manipulate(manipulations, idx)
            self.manipulation_status.build_obfuscated_apk()
            self.manipulation_status.sign_obfuscated_apk()
            self.manipulation_status.align_obfuscated_apk()
        except Exception as _:
            self.logger.exception("Error during APK manipulation")
            obfuscated_apk_path = None
        finally:
            self.manipulation_status.clean_iter(idx)

        return obfuscated_apk_path

    def get_error_free_manipulations(  # noqa: C901
        self,
        manipulations: Manipulations,
        n_jobs: int = 1,
        cache_dir: Optional[str] = None,
    ) -> Manipulations:
        """
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

        error_free_manipulations = self._load_error_free_manipulations(
            manipulations, cache_dir
        )

        if error_free_manipulations is not None:
            return error_free_manipulations

        # [Step 1] Test a build without applying manipulations, if the APK cannot be built,
        # it retries without decompiling resources and considering only main dex files.
        try:
            self.manipulation_status.build_obfuscated_apk()
        except Exception as _:  # noqa: BLE001
            self.clean_data()

            if Path(self.manipulation_status.obfuscated_apk_path).exists():
                Path(self.manipulation_status.obfuscated_apk_path).unlink()
            try:
                self.logger.debug(
                    "Error during APK building: trying without decompiling "
                    "resources and considering only main dex files"
                )
                self.manipulation_status._is_decoded = False
                self.manipulation_status.decode_apk(
                    skip_resources=True, only_main_dex=self._only_main_dex
                )
                self.manipulation_status.build_obfuscated_apk()

                # Remove the AttClassRename obfuscator if the APK is built
                # without decompiling resources and considering only main dex
                self.obfuscators = [
                    o for o in self.obfuscators if not isinstance(o, AttClassRename)
                ]
            except Exception as _:
                self.clean_data()
                self.logger.exception("The APK cannot be build")
                raise
        finally:
            if Path(self.manipulation_status.obfuscated_apk_path).exists:
                Path(self.manipulation_status.obfuscated_apk_path).unlink()

        # [Step 2] Retrieve error free manipulations
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

            for applied_manipulations, manipulation in zip(
                applied_manipulations_list, manipulations_list, strict=True
            ):
                if applied_manipulations is None:
                    if len(manipulation) > 1:
                        n = min(n_jobs, len(manipulation))
                        idxs = manipulation.get_idxs()
                        sub_manipulations = [
                            manipulation.get_manipulations_from_vector(idxs[i::n])
                            for i in range(n)
                        ]
                        _recurse_apply_manipulations(sub_manipulations)
                else:
                    error_free_manipulations.inject.extend(applied_manipulations.inject)
                    error_free_manipulations.obfuscate.extend(
                        applied_manipulations.obfuscate
                    )

        _recurse_apply_manipulations(manipulations)

        self._save_error_free_manipulations(error_free_manipulations, cache_dir)

        return error_free_manipulations

    def model_probing(
        self,
        classifier: BaseModel,
        manipulation_space: ManipulationSpace,
        init_score: float,
    ) -> None:
        """
        Probe the classifier to understand which features are significant for
        the classification process.

        Parameters
        ----------
        classifier : Classifier
            Classifier to probe
        manipulation_space : ManipulationSpace
            Manipulation space
        """

        def _model_probing(
            idx: int,
            manipulator: Manipulator,
            manipulations: Manipulations,
            classifier: BaseModel,
            init_score: float,
        ) -> tuple[float, bool]:
            apk_path = manipulator.manipulate(manipulations, idx)
            _, scores = classifier.classify([apk_path])
            return scores.item(), init_score != scores.item()

        self.logger.info("Probing the classifier")

        injections_by_category = manipulation_space.get_injections_by_categories()
        obfuscations_by_category = manipulation_space.get_obfuscations_by_categories()

        for feat_category, feats in {
            **injections_by_category,
            **obfuscations_by_category,
        }.items():
            if feat_category in injections_by_category:
                manipulations = Manipulations(feats, [])
            else:
                manipulations = Manipulations([], feats)

            result = _model_probing(
                0,
                self,
                manipulations,
                classifier,
                init_score,
            )

            self.logger.debug("Probing results for %s: %.2f", feat_category, result[0])

            if not result[1]:
                manipulation_space.disable_category(feat_category)

            if Path(self.manipulation_status.obfuscated_apk_path).exists():
                Path(self.manipulation_status.obfuscated_apk_path).unlink()

    def get_manipulated_apks_dir(self, file: str) -> str:
        """
        Build the path containing the manipulated APK.

        Parameters
        ----------
        file : str
            File name of the manipulated APK

        Returns
        -------
        str
            Path to the manipulated APK
        """
        return str(Path(self._manipulated_apks_dir) / file)

    def clean_data(self) -> None:
        """Clean the data of the ManipulationStatus object."""
        self.manipulation_status.clean_data()

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
        except Exception as _:  # noqa: BLE001
            self.clean_data()

            if Path(self.manipulation_status.obfuscated_apk_path).exists():
                Path(self.manipulation_status.obfuscated_apk_path).unlink()

            try:
                self.logger.debug(
                    "Error while decoding APK: trying again"
                    "considering only main dex files"
                )
                self.manipulation_status.decode_apk(only_main_dex=True)
                self._only_main_dex = True
            except Exception as _:
                self.clean_data()
                if Path(self.manipulation_status.obfuscated_apk_path).exists():
                    Path(self.manipulation_status.obfuscated_apk_path).unlink()

                self.logger.exception("Error during APK decoding")
                raise

    def _manipulate(self, manipulations: Manipulations, idx: int) -> None:  # noqa: C901
        self.manipulation_status.reset()
        self.manipulation_status.update_path(idx)

        # Extract the features to inject from the manipulations
        for feature in manipulations.inject:
            splitted_feat = feature.split("::")
            feat_type, feat = splitted_feat[0], splitted_feat[1]

            if feat_type == "urls":
                self.manipulation_status.urls_to_inject.add(feat)
            elif feat_type == "api_calls":
                self.manipulation_status.apis_to_inject.add(feat)

        #  Extract the features to obfuscate from the manipulations
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

    def _load_error_free_manipulations(
        self, manipulations: Manipulations, cache_dir: str
    ) -> Manipulations | None:
        """Try to load the saved error free manipulations for an APK."""
        if cache_dir:
            dir_path = Path(cache_dir) / f"{Path(self._apk_path).stem}"

            if len(manipulations.inject) > 0 and len(manipulations.obfuscate) == 0:
                filename = f"{Path(self._apk_path).stem}.inject.pkl"
            elif len(manipulations.inject) == 0 and len(manipulations.obfuscate) > 0:
                filename = f"{Path(self._apk_path).stem}.obfuscate.pkl"
            else:
                filename = f"{Path(self._apk_path).stem}.all.pkl"

            if (dir_path / filename).exists():
                return pickle.load((Path(dir_path) / filename).open("rb"))  # noqa: S301

        return None

    def _save_error_free_manipulations(
        self, error_free_manipulations: Manipulations, cache_dir: str
    ) -> None:
        """Save the error free manipulations for an APK."""
        if cache_dir:
            dir_path = Path(cache_dir) / f"{Path(self._apk_path).stem}"
            dir_path.mkdir(parents=True, exist_ok=True)

            if (
                len(error_free_manipulations.inject) > 0
                and len(error_free_manipulations.obfuscate) == 0
            ):
                filename = f"{Path(self._apk_path).stem}.inject.pkl"
            elif (
                len(error_free_manipulations.inject) == 0
                and len(error_free_manipulations.obfuscate) > 0
            ):
                filename = f"{Path(self._apk_path).stem}.obfuscate.pkl"
            else:
                filename = f"{Path(self._apk_path).stem}.all.pkl"

            pickle.dump(error_free_manipulations, (dir_path / filename).open("wb"))


# ------------------
# Utility functions
# ------------------


def _apply_manipulations(
    idx: int, manipulator: Manipulator, manipulations_list: list[Manipulations]
) -> Manipulations:
    """
    Apply the manipulations to the APK (only for get_error_free_manipulations).

    Parameters
    ----------
    idx : int
        Index of the manipulation
    manipulator : Manipulator
        Manipulator object
    manipulations_list : list[Manipulations]
        List of manipulations to apply

    Returns
    -------
    Manipulations
        Manipulations applied
    """
    manipulator.manipulation_status.obfuscated_apk_path = (
        manipulator.get_manipulated_apks_dir(
            f"{Path(manipulator._apk_path).stem}_{uuid.uuid1().hex}.apk"
        )
    )

    manipulations = manipulations_list[idx]

    try:
        manipulator._manipulate(manipulations, idx)
        manipulator.manipulation_status.build_obfuscated_apk()
    except Exception as _:  # noqa: BLE001
        manipulations = None
    finally:
        manipulator.manipulation_status.clean_iter(idx)
        if Path(manipulator.manipulation_status.obfuscated_apk_path).exists():
            Path(manipulator.manipulation_status.obfuscated_apk_path).unlink()

    return manipulations

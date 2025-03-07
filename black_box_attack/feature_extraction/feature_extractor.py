"""
The module contains the FeatureExtractor class, which is used to extract features
from APK files. The extracted features are saved in JSON format and can be reused
if they already exist.
"""

import json
import logging
from pathlib import Path

from feature_extraction.base_feature_extractor import BaseFeatureExtractor

from .apk_analyzer import process_apk


class FeatureExtractor(BaseFeatureExtractor):
    """Feature extractor based on Androguard library."""

    def __init__(self, logging_level: int = logging.INFO) -> None:
        """
        Create and inizialize the feature extractor.

        Parameters
        ----------
        logging_level: int
            Set the verbosity of the logger.
        """
        super(__class__, self).__init__()
        self._set_logger(logging_level)

    def _extract_features(self, apk: str) -> list | None:
        """
        Extract the features from the apk file.

        Parameters
        ----------
        apk: str
            The path to the apk file.
        """
        if self._features_out_dir is not None:
            file_name = Path(self._features_out_dir) / (Path(apk).stem + ".json")

            if Path(file_name).exists():
                self.logger.info("Feature for %s were already extracted", apk)
                with Path(file_name).open("r") as js:
                    data = json.load(js)
                    return [f"{k}::{v}" for k in data for v in data[k] if data[k]]

        if Path(apk) and Path(apk).stat().st_size > 0:
            result = process_apk(apk, self._features_out_dir, self.logger)
            self.logger.info("%s features were successfully extracted", apk)
            return result

        self.logger.error("%s does not exist or is an empty file", apk)

        return None

    def _set_logger(self, logging_level: int) -> None:
        """
        Set the logger for the feature extractor.

        Parameters
        ----------
        logging_level: int
            Set the verbosity of the logger.
        """
        logging.basicConfig(
            level   = logging_level,
            datefmt = "%Y/%m/%d %H:%M:%S",
            format  = "%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s: "
            "%(message)s",
        )
        error_handler = logging.StreamHandler()
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s: %(message)s"
            )
        )
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.addHandler(error_handler)
        logging.getLogger("androguard.dvm").setLevel(logging.CRITICAL)
        logging.getLogger("androguard.core.api_specific_resources").setLevel(
            logging.CRITICAL
        )
        logging.getLogger("androguard.axml").setLevel(logging.CRITICAL)
        logging.getLogger("androguard.apk").setLevel(logging.CRITICAL)

"""
The module provides functionality to download APK files from AndroZoo using their SHA256
hash.
"""

import hashlib
import logging
from multiprocessing import Pool
from pathlib import Path

import requests

ANDROZOO_BASE_URL = "https://androzoo.uni.lu/api/download?apikey={0}&sha256={01}"


class APKDownloader:
    """
    Class for downloading APK files from AndroZoo, given their SHA256 hash.
    An APK key is required and can be requested from AndroZoo maintainers.

    Part of this code is taken from:
    https://github.com/ArtemKushnerov/az/blob/master/modules/services/dataset_downloader.py
    """

    def __init__(
        self,
        androzoo_api_key: str,
        out_dir         : str,
        logging_level   : int = logging.INFO
    ) -> None:
        """
        Initialize the APKDownloader object.

        Parameters
        ----------
        androzoo_api_key : str
            The AndroZoo API key.
        out_dir : str
            The directory where the downloaded APK files will be saved.
        logging_level : int
            Set the verbosity of the logger.
        """
        self.androzoo_api_key = androzoo_api_key
        self.out_dir = out_dir

        if not Path(out_dir):
            Path(out_dir).mkdir(parents=True)

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging_level)

    def download_apks(self, apks_sha256: list[str], n_jobs: int = 1) -> None:
        """
        Download a list of APK files from AndroZoo, given their SHA256 hash.

        Parameters
        ----------
        apks_sha256 : list of str
            List containing the SHA256 hashes of the APK files to download.
        n_jobs : int
            The number of concurrent threads used for downloading the APK
            files. It must be between 1 and 20. Default is 1.
        """
        if n_jobs < 1 or n_jobs > 20:
            raise ValueError("`n_jobs` must be between 1 and 20")

        self.logger.info(
            "Starting download of %d APKs with %d concurrent threads",
            len(apks_sha256), n_jobs
        )

        with Pool(n_jobs) as pool:
            pool.map(self._download_apk, apks_sha256)

    @staticmethod
    def _check_hash(file_path: str, sha256: str) -> bool:
        """
        Compute the SHA256 hash on a given file and check if it matches the
        target one.

        Parameters
        ----------
        file_path : str
            Path of the file to check.
        sha256 : str
            Target SHA256 hash.

        Returns
        -------
        bool
            True if the two hashes match, False otherwise.
        """
        with Path(file_path).open("rb") as f:
            file_bytes = f.read()
            sha256_hash = hashlib.sha256(file_bytes).hexdigest().upper()
        return sha256.upper() == sha256_hash

    def _download_apk(self, apk_sha256: str) -> None:
        """
        Download a single APK file from AndroZoo, given its SHA256 hash.

        Parameters
        ----------
        apk_sha256 : str
            The SHA256 hash of the APK file to download.
        """
        apk = apk_sha256.upper()
        apk_save_path = Path(self.out_dir) / f"{apk}.apk"

        try:
            if Path(apk_save_path).exists():
                # apk already downloaded
                if __class__._check_hash(apk_save_path, apk):
                    self.logger.debug("%s.apk already downloaded", apk)
                    return

                self.logger.debug(
                    "%s.apk already downloaded but the file is corrupted, downloading again",
                    apk
                )
                Path(apk_save_path).unlink()

            self.logger.debug("Downloading %s.apk", apk)

            apk_url = ANDROZOO_BASE_URL.format(self.androzoo_api_key, apk)
            response = requests.get(apk_url)
            code = response.status_code
            if code == 200:
                with Path(apk_save_path).open("wb") as out_file:
                    out_file.write(response.content)
                assert __class__._check_hash(apk_save_path, apk)
            else:
                self.logger.debug("HTTP code for %s.apk is %d", apk, code)
        except:
            self.logger.exception(
                "Unexpected error while downloading %s.apk", apk
            )

"""
The module provides functionality for evaluating a classifier on goodware and
adversarial test sets.
"""

import logging
import os
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pandas as pd
from models.base import BaseModel

from .apk_downloader import APKDownloader
from .attack import BBPSAttack


def _download_apks(
    androzoo_api_key: str, ds_file: str, out_dir: str, n_jobs: int = 1
) -> None:
    n_jobs = min(n_jobs, 20)
    downloader = APKDownloader(androzoo_api_key, out_dir)

    with ZipFile(ds_file, "r", ZIP_DEFLATED) as z:
        ds_csv = pd.concat(
            [pd.read_csv(z.open(f))[["sha256"]] for f in z.namelist()],
            ignore_index=True,
        )
        apks_sha256 = ds_csv.sha256.to_numpy().tolist()

    downloader.download_apks(apks_sha256, n_jobs=n_jobs)


def evaluate(classifier: BaseModel, config) -> list[dict]:
    """
    Evaluate the classifier on the goodware and the adversarial test set dataset.

    Parameters
    ----------
    classifier : BaseModel
        The classifier to evaluate.

    config : Config
        The configuration object.

    Returns
    -------
    list
        A list of dict, each containing the classification results of the
        goodware test set, the adversarial test set, and the adversarial test set
        after the attack
    """
    ts_fp_check_dir = config.TS_FP_CHECK_DIR
    ts_adv_dir = config.TS_ADV_DIR
    manipulated_apks_dir = config.MANIPULATED_APKS_DIR

    if config.DOWNLOAD_APKS:
        ts_fp_check_ds = config.TS_FP_CHECK
        _download_apks(
            config.AZOO_API_KEY, ts_fp_check_ds, ts_fp_check_dir, config.N_JOBS
        )
        ts_adv_ds = config.TS_ADV
        _download_apks(config.AZOO_API_KEY, ts_adv_ds, ts_adv_dir, config.N_JOBS)

    results = []

    # [Step 1] Classifies the APKs in the test set of the goodware dataset

    ts_fp_check = sorted(
        [str(Path(ts_fp_check_dir) / apk) for apk in os.listdir(ts_fp_check_dir)],
        key=os.path.getctime,
    )
    # y_pred, scores = classifier.classify(ts_fp_check)

    # results.append(
    #     {
    #         sha256: [int(y), float(s)]
    #         for sha256, y, s in zip(
    #             [Path(apk).stem for apk in ts_fp_check],
    #             y_pred,
    #             scores,
    #             strict=True,
    #         )
    #     }
    # )

    # [Step 2] Classifies the APKs in the test set of the adversarial dataset

    ts_adv = sorted(
        [str(Path(ts_adv_dir) / apk) for apk in os.listdir(ts_adv_dir)],
        key=os.path.getctime,
    )
    # y_pred, scores = classifier.classify(ts_adv)

    # results.append(
    #     {
    #         sha256: [int(y), float(s)]
    #         for sha256, y, s in zip(
    #             [Path(apk).stem for apk in ts_adv],
    #             y_pred,
    #             scores,
    #             strict=True,
    #         )
    #     }
    # )

    #
    # [Step 3] Performs adversarial attacks
    #
    attack = BBPSAttack(
        classifier=classifier,
        manipulated_apks_dir=manipulated_apks_dir,
        logging_level=logging.DEBUG,
        features_dir="/disk1/home/cscano/black-box-android/data/features",
    )

    adv_results = attack.run(
        ts_adv[:1],
        ts_fp_check[:1],
        n_iterations=5,
        n_features=100,
        n_jobs=config.N_JOBS,
        n_candidates=20,
    )

    # results.append(
    #     {
    #         sha256: [int(adv_result[0]), float(adv_result[1])]
    #         for sha256, adv_result in zip(
    #             [Path(apk).stem for apk in ts_adv],
    #             adv_results,
    #             strict=True,
    #         )
    #     }
    # )

    return results

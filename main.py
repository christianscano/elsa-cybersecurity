"""
Main module for loading a classifier and evaluating it.

This script allows the user to load a trained classifier from a specified Python module
and evaluate it using a predefined evaluation function. The results of the evaluation
are then saved to a JSON file.

Usage:
    python main.py --clf-loader-path <path_to_classifier_loader>

Example:
    python main.py --clf-loader-path android-detectors/src/loaders/drebin_loader.py
"""

import argparse
import importlib.util
import json
import sys
from pathlib import Path

import config
from black_box_attack import evaluate


def _load_classifier(clf_loader_path: str) -> object:
    """
    Load a classifier from the specified Python module.

    Parameters
    ----------
    clf_loader_path : str
        Path of a Python module containing a `load()` method that returns a trained
        classifier.

    Returns
    -------
    object
        Trained classifier loaded from the specified Python module.
    """
    spec = importlib.util.spec_from_file_location("module.name", clf_loader_path)
    module = importlib.util.module_from_spec(spec)

    sys.modules["module.name"] = module
    spec.loader.exec_module(module)

    return module.load()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--clf-loader-path",
        type = str,
        help = "Path of a Python module containing a `load()` method that "
        "returns a trained classifier.",
    )

    # args = parser.parse_args()

    # classifier = _load_classifier(args.clf_loader_path)

    classifier = _load_classifier("android-detectors/src/loaders/drebin_loader.py")

    results = evaluate(classifier, config)

    with Path("results/results.json").open("w") as f:
        json.dump(results, f, indent=4)

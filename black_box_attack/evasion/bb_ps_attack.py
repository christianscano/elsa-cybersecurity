"""TODO: Add a description here."""

import contextlib
import logging
import os
import random
import tempfile
from itertools import chain
from pathlib import Path

import numpy as np
from models.base import BaseModel

from black_box_attack.feature_extraction import FeatureExtractor
from black_box_attack.manipulations import Manipulations, ManipulationSpace, Manipulator
import nevergrad as ng


class BBPSAttack:
    """Class for performing black-box problem-space attacks on APK files."""

    def __init__(
        self,
        classifier: BaseModel,
        manipulated_apks_dir: str,
        logging_level: int = logging.INFO,
        features_dir: str | None = None,
    ) -> None:
        """
        Genetic black-box problem-space attack that manipulates the APK files
        of malware samples to evade the classifier.
        The attack need a set of goodware samples from which to initialize the
        population.
        The optimization is performed on individuals which consists of
        manipulation vectors, that contain the indexes of the features that can
        be manipulated (injected or obfuscated).

        Parameters
        ----------
        classifier : BaseModel
            The trained classifier to attack.
        manipulated_apks_dir : str
            The directory where the adversarial APKs will be stored.
        logging_level : int
            Set the verbosity of the logger.
        features_dir : string | None
            If provided, the extracted features will be stored in this path and
            retrieved from it if available.
        """
        self.clf = classifier

        self.manipulated_apks_dir = manipulated_apks_dir
        if not Path(manipulated_apks_dir).exists():
            Path(manipulated_apks_dir).mkdir(parents=True)

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging_level)

        # Private attributes
        self._feature_extractor = FeatureExtractor(logging_level=logging.ERROR)
        self._features_cache = features_dir
        self._goodware_features = None
        self._query_budget = None
        self._n_features = None
        self._n_candidates = None
        self._stagnation = None
        self._n_jobs = None
        self._logging_level = logging_level

    def run(
        self,
        malware_samples: list[str],
        goodware_samples: list[str],
        query_budget: int = 100,
        n_features: int = 5,
        n_candidates: int = 5,
        stagnation: int = 5,
        seed: int = 0,
        n_jobs: int = 1,
    ) -> list[tuple[int, float, str]]:
        """
        Run the attack.

        Parameters
        ----------
        malware_samples : list of str
            List with the absolute path of each malware APK file to attack.
        goodware_samples : list of str
            List with the absolute path of each goodware APK file to be used
            for the attack initialization.
        n_iterations : int
            Max number of iterations for the genetic attack.
        n_features : int
            Number of features to be added during the attack.
        n_candidates : int
            Number of considered goodware samples to initialize the population.
        stagnation : int
            Number of generations without improvement to stop the attack.
        seed : int
            Seed for the random number generator.
        n_jobs : int
            Number of parallel jobs to run during the attack.

        Returns
        -------
        list of tuples (int, float, str)
            For each malware sample, a tuple is returned containing the
            predicted label and score after the attack and the path of the
            manipulated APK file. If a sample is already undetected, the tuple
            will contain the predicted label and score and the path of the
            original sample.
        """
        self._query_budget = query_budget
        self._n_features = n_features
        self._n_candidates = n_candidates
        self._stagnation = stagnation
        self._n_jobs = n_jobs

        random.seed(seed)
        np.random.seed(seed)  # noqa: NPY002

        # Extract the features to inject from the selected goodwares
        self._generate_candidate_injections(goodware_samples)

        results = []
        for i, sample in enumerate(malware_samples):
            self.logger.info("Attacking sample %d", i)
            results.append(self._run_attack(sample))

        return results

    # ----------------
    # Private methods
    # ----------------

    def _generate_candidate_injections(self, goodware_samples: list[str]) -> None:
        """
        Extract the features from the provided goodware samples, select only
        features that can be manipulated (added).

        Parameters
        ----------
        goodware_samples : list of str
            List of paths of the goodware samples.
        """
        self._goodware_features = []

        self.logger.debug("Generating candidates")

        goodware_features = self._feature_extractor.extract_features(
            goodware_samples, out_dir=self._features_cache
        )

        self._goodware_features = ManipulationSpace.get_valid_injections(
            list(chain(*goodware_features))
        )

    def _run_attack(self, malware_sample: str) -> tuple[int, float, str]:
        """
        Run the attack on a single sample.

        Parameters
        ----------
        malware_sample : str
            The absolute path of the malware APK file to attack.

        Returns
        -------
        tuple (int, float, str)
            The predicted label and score after the attack and the path of the
            manipulated
        """
        # [Step 1] Initial classification
        label, score = self.clf.classify([malware_sample])
        label, score = label.item(), score.item()
        if label == 0:
            self.logger.debug("Skipping sample, it is not detected as malware")
            return label, score, malware_sample

        self.logger.debug("Initial confidence: %s", score)

        adv_apk_path = malware_sample

        # [Step 2] Attack
        manipulator = Manipulator(
            malware_sample, self.manipulated_apks_dir, logging_level=self._logging_level
        )

        manipulation_space = self._init_attack(malware_sample, manipulator, score)
        optimizer = self._init_optimizer()
        
        """
        x_adv, delta = self._init_attack_manipulation(samples)
        self.optimizer = self._init_optimizer(model, delta)
        budget = 0
        self._init_best_tracking(delta)
        while budget < self.query_budget:
            x_adv, _ = self._apply_manipulation(samples, delta)
            scores = model.decision_function(x_adv)
            loss = self.loss_function(scores, target) * multiplier
            delta = self._optimizer_step(delta, loss)
            budget += self._consumed_budget()
            self._track(budget, loss, scores, x_adv, delta)
            self._track_best(loss, delta)
        best_delta = self._get_best_delta()
        best_x, _ = self._apply_manipulation(samples, best_delta)
        return best_x, self._best_delta
        """

        budget = 0
        while budget < self._query_budget:
            pass


        # [Step 3] Cleanup
        if manipulator:
            manipulator.clean_data()

        for tmp_f in os.listdir(tempfile.gettempdir()):
            if tmp_f.startswith("APKTOOL") or tmp_f.endswith(".apk"):
                with contextlib.suppress(FileNotFoundError):
                    (Path(tempfile.gettempdir()) / tmp_f).unlink()

        return label, score, adv_apk_path

    def _init_attack(
        self, malware_sample: str, manipulator: Manipulator, init_score: float
    ) -> ManipulationSpace:
        """
        Prepare the manipulation space and probe the classifier under analysis to remove
        the features that are not relevant for the attack.

        Parameters
        ----------
        malware_sample : str
            The absolute path of the malware APK file to attack.
        manipulator : Manipulator
            Manipulator object.

        Returns
        -------
        ManipulationSpace
            Object containing the features that can be manipulated.
        """
        malware_features = self._feature_extractor.extract_features(
            [malware_sample], out_dir=self._features_cache
        )
        manipulation_space = self._build_manipulation_space(
            malware_features[0], manipulator
        )

        manipulator.model_probing(self.clf, manipulation_space, init_score=init_score)

        if not manipulation_space:
            raise Exception("No manipulation can be applied.")

        return manipulation_space

    def _build_manipulation_space(
        self, malware_features: list[str], manipulator: Manipulator
    ) -> ManipulationSpace:
        """
        Create the manipulation space, containing the features that can be
        manipulated (injected or obfuscated).

        Parameters
        ----------
        malware_features : list[str]
            Textual features of the malware sample.
        manipulator : Manipulator
            Manipulator object

        Returns
        -------
        ManipulationSpace
            Object containing the features that can be manipulated.
        """
        self.logger.debug("Building manipulation space")

        manipulation_space = ManipulationSpace(
            self._goodware_features, malware_features
        )

        error_free_injections = manipulator.get_error_free_manipulations(
            manipulation_space.get_all_injections(), self._n_jobs, self._features_cache
        )

        error_free_obfuscations = manipulator.get_error_free_manipulations(
            manipulation_space.get_all_obfuscations(),
            self._n_jobs,
            self._features_cache,
        )

        manipulation_space.set_error_free_manipulations(
            Manipulations(
                error_free_injections.inject, error_free_obfuscations.obfuscate
            )
        )

        return manipulation_space

    def _get_random_manipulation_vector(
        self, manipulation_space: ManipulationSpace
    ) -> np.ndarray:
        """
        Generate a random manipulation vector, that contains the indexes of
        the features in the manipulation space that can be modified.

        Parameters
        ----------
        manipulation_space: ManipulationSpace
            Object containing the features that can be manipulated.

        Returns
        -------
        np.ndarray
            The manipulation vector.
        """
        return np.random.choice(  # noqa: NPY002
            np.arange(len(manipulation_space)),
            replace=False,
            size=min(len(manipulation_space), self._n_features),
        )

import numpy as np


class Feature:
    """Class to represent a single feature."""

    def __init__(self, inject: bool, obfuscate: bool) -> None:
        """
        Create and initialize the feature object.

        Parameters
        ----------
        inject : bool
            True if the feature can be injected
        obfuscate : bool
            True if the feature can be obfuscated
        """
        self.inject    = inject
        self.obfuscate = obfuscate


FEATURES = {
    "activities"      : Feature(inject=False, obfuscate=True),
    "services"        : Feature(inject=False, obfuscate=True),
    "providers"       : Feature(inject=False, obfuscate=True),
    "receivers"       : Feature(inject=False, obfuscate=True),
    "api_calls"       : Feature(inject=True,  obfuscate=True),
    "suspicious_calls": Feature(inject=False, obfuscate=True),
    "urls"            : Feature(inject=True,  obfuscate=True),
}


class Manipulations:
    """Class to represent the manipulations."""

    def __init__(self, inject: list, obfuscate: list) -> None:
        """
        Create and initialize the manipulations object.

        Parameters
        ----------
        inject : list
            List of injections (goodware)
        obfuscate : list
            List of obfuscations
        """
        self._inject    = inject
        self._obfuscate = obfuscate

    @property
    def inject(self) -> list:
        """Return the list of injections."""
        return self._inject

    @property
    def obfuscate(self) -> list:
        """Return the list of obfuscations."""
        return self._obfuscate

    def __len__(self) -> int:
        """Return the number of possible manipulations."""
        return len(self.inject) + len(self.obfuscate)

    def __bool__(self) -> bool:
        """Return True if there are manipulations."""
        return self.__len__() > 0

    def get_idxs(self) -> np.NDArray:
        """Return the indexes of the manipulations."""
        inject_idx    = [i for i, _ in enumerate(self.inject)]
        obfuscate_idx = [i + len(self.inject) for i, _ in enumerate(self.obfuscate)]

        return np.array(inject_idx + obfuscate_idx)

    def get_manipulations_from_vector(
        self,
        manipulation_vector: np.NDArray
    ) -> "Manipulations":
        """
        Return the manipulations from the manipulation vector.

        Parameters
        ----------
        manipulation_vector : np.NDArray
            Manipulation vector

        Returns
        -------
        Manipulations
            Manipulations object
        """
        inject_idx    = manipulation_vector[manipulation_vector < len(self.inject)]
        obfuscate_idx = manipulation_vector[
            manipulation_vector >= len(self.inject)
        ] - len(self.inject)

        return Manipulations(
            [self.inject[i] for i in inject_idx],
            [self.obfuscate[i] for i in obfuscate_idx],
        )


class ManipulationSpace(Manipulations):
    """Class to represent the manipulation space."""

    def __init__(self, valid_injections: list, malware_features: list) -> None:
        """
        Initialize the manipulation space with the valid injections and obfuscations.

        Parameters
        ----------
        valid_injections : list
            List of valid injections (goodware)
        malware_features : list
            List of malware features
        """
        inject    = [v for v in valid_injections if v not in malware_features]
        obfuscate = self.get_valid_obfuscations(
            [f for f in malware_features if f not in inject]
        )
        super(__class__, self).__init__(inject, obfuscate)

    def get_all_manipulations(self) -> Manipulations:
        """Reutrn all manipulations space."""
        return Manipulations(self.inject, self.obfuscate)

    def get_all_injections(self) -> Manipulations:
        """Return all possible injections."""
        return Manipulations(self.inject, [])

    def get_all_obfuscations(self) -> Manipulations:
        """Return all possible obfuscations."""
        return Manipulations([], self.obfuscate)

    def get_vector_from_manipulations(self, manipulations: Manipulations) -> np.NDArray:
        """
        Return the manipulation vector from the manipulations.

        Parameters
        ----------
        manipulations : Manipulations
            Manipulations object

        Returns
        -------
        np.NDArray
            Manipulation vector
        """
        inject_idx    = [i for i, _ in enumerate(manipulations.inject)]
        obfuscate_idx = [
            i + len(self.inject) for i, _ in enumerate(manipulations.obfuscate)
        ]
        return np.array(inject_idx + obfuscate_idx)

    def set_error_free_manipulations(self, error_free_manipulations: Manipulations) -> None:
        """
        Set the error free manipulations.

        Parameters
        ----------
        error_free_manipulations : Manipulations
            Error free manipulations
        """
        self._inject    = list(error_free_manipulations.inject)
        self._obfuscate = list(error_free_manipulations.obfuscate)

    @staticmethod
    def get_valid_obfuscations(malware_features: list) -> list:
        """
        Return the valid obfuscations from the malware features.

        Parameters
        ----------
        malware_features : list
            List of malware features

        Returns
        -------
        list
            List of valid obfuscations
        """
        return [
            feat for feat in malware_features if FEATURES[feat.split("::")[0]].obfuscate
        ]

    @staticmethod
    def get_valid_injections(feature_list: list) -> list:
        """
        Retrive the valid injections from the feature list.

        Parameters
        ----------
        feature_list : list
            List of features

        Returns
        -------
        list
            List of valid injections
        """
        return [
            feat
            for features in feature_list
            for feat in features
            if FEATURES[feat.split("::")[0]].inject
            and not (
                (
                    feat.startswith(("api_calls::", "suspicious_calls::"))
                )
                and not (
                    feat.endswith(("()V", "()Z", "()I"))
                )
            )
        ]

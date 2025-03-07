""""""

from maltorch.adv.evasion.gradfree_attack import GradientFreeBackendAttack
from typing import Union, Callable
from secmlt.trackers import Tracker
from maltorch.adv.evasion.base_optim_attack_creator import (
    BaseOptimAttackCreator,
    OptimizerBackends,
)


class AndroidBlackBoxAttack(GradientFreeBackendAttack):
    def __init__(
        self,
        query_budget: int,
        trackers: Union[list[Tracker], Tracker] = None,
    ) -> None:
        """"""

        # Define nevergrad optimizer

        # Define loss function

        # Define manipulation function

        super().__init__(
            y_target=
            query_budget=
            loss_function=
            initializer=
            manipulation_function=
            optimizer_cls=
            trackers=
        )


class AndroidBlackBox(BaseOptimAttackCreator):
    """TODO: Add docstring"""

    @staticmethod
    def get_backends() -> set[str]:
        return {OptimizerBackends.NG}

    @staticmethod
    def _get_nevergrad_implementation() -> type[AndroidBlackBoxAttack]:
        return AndroidBlackBoxAttack

    def __new__(cls, query_budget: int, trackers: Union[list[Tracker], Tracker]) -> Callable:
        return AndroidBlackBoxAttack(
            query_budget=query_budget,
            trackers=trackers,
        )
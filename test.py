import nevergrad as ng
from nevergrad.optimization.differentialevolution import DifferentialEvolution

"""
Interesting optimizer:
- DifferentialEvolution
- EvolutionStrategy
- ParametrizedOnePlusOne
- TwoPointsDE
"""

possible_api = [
    "activtiy:read",
    "api_call:read",
    "api_call:write",
    "api_call:delete",
]

def l1_norm_constraint(x):
    return perturbation_budget - sum(abs(v) for v in x.values())

# Settings
perturbation_budget = 2.0  # Number of pixels allowed to change
query_budget = 100  # Number of queries allowed

# Define Nevergrad parameterization
param_dict = {api: ng.p.Choice([-1, 0, 1]) for api in possible_api}

optimizer_cls = DifferentialEvolution(popsize=5, crossover="twopoints")
optimizer = optimizer_cls(parametrization=ng.p.Dict(**param_dict), budget=query_budget)

optimizer.parametrization.register_cheap_constraint(l1_norm_constraint)

delta = optimizer.ask()

print(delta.value)

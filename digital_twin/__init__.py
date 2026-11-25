"""Security Digital Twin package for SENTINEL AI."""

from digital_twin.compatibility_checker import CompatibilityWarning, check_compatibility
from digital_twin.configuration_snapshot import (
    DigitalTwinSnapshotError,
    VirtualSnapshot,
    create_virtual_snapshot,
)
from digital_twin.cookie_simulator import CookieSimulationResult, simulate_cookie_policy
from digital_twin.csp_simulator import RECOMMENDED_CSP, CspSimulationResult, simulate_csp_policy
from digital_twin.simulation_evaluator import EvaluatedSimulation, evaluate_virtual_configuration
from digital_twin.simulation_history import get_simulation_details, list_simulations
from digital_twin.twin_engine import DigitalTwinRunResult, run_digital_twin_simulation

__all__ = [
    "CompatibilityWarning",
    "CookieSimulationResult",
    "CspSimulationResult",
    "DigitalTwinRunResult",
    "DigitalTwinSnapshotError",
    "EvaluatedSimulation",
    "RECOMMENDED_CSP",
    "VirtualSnapshot",
    "check_compatibility",
    "create_virtual_snapshot",
    "evaluate_virtual_configuration",
    "get_simulation_details",
    "list_simulations",
    "run_digital_twin_simulation",
    "simulate_cookie_policy",
    "simulate_csp_policy",
]

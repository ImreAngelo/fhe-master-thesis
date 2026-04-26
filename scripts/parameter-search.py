"""
Optuna driver for tuning RGSW parameters against test-rgsw.

For each trial we sample (gadget_base, gadget_decomposition), invoke the test
binary with those overrides plus a fixed --gtest_filter, and minimise wall
time among configs whose tests still pass. Failing trials are pruned.

Run via `make tune-rgsw` (the venv at .venv/ ships Optuna).
"""

import subprocess
import time
from pathlib import Path

import optuna

REPO_ROOT = Path(__file__).resolve().parents[1]
BINARY = REPO_ROOT / "build" / "test" / "test-rgsw"

# Single representative case so trials don't have to satisfy every shape at once.
# Swap this filter to retune for a different scenario.
GTEST_FILTER = "RGSW.b10"

PER_TRIAL_TIMEOUT_S = 120


def objective(trial: optuna.Trial) -> float:
    gadget_base          = trial.suggest_int("gadget_base", 1, 64)
    gadget_decomposition = trial.suggest_int("gadget_decomposition", 1, 16)

    cmd = [
        str(BINARY),
        f"--gadget_base={gadget_base}",
        f"--gadget_decomposition={gadget_decomposition}",
        f"--gtest_filter={GTEST_FILTER}",
        "--gtest_color=no",
    ]

    start = time.perf_counter()
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=PER_TRIAL_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        raise optuna.TrialPruned()
    elapsed = time.perf_counter() - start

    if result.returncode != 0:
        raise optuna.TrialPruned()

    return elapsed


def main() -> None:
    if not BINARY.exists():
        raise SystemExit(f"test binary not found at {BINARY}; run `make test-rgsw` first")

    study = optuna.create_study(direction="minimize")
    study.optimize(objective, n_trials=200)
    print(f"best params: {study.best_params}")
    print(f"best time: {study.best_value * 1000} ms")


if __name__ == "__main__":
    main()

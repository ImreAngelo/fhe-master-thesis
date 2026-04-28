"""
Optuna driver for tuning parameters of one of the test-* binaries.

Usage: scripts/parameter-search.py <target>   (e.g. rgsw, main)
       N_JOBS=4 scripts/parameter-search.py rgsw

Each target declares its own search space and gtest filter (see TARGETS).
Trials launch the test binary with --<flag>=<value> overrides; subprocesses
are killed once they exceed LEADER_KILL_MARGIN × current best so we don't
finish a run we already know is slower than the leader. Pruned trials are
excluded from the sampler's likelihood model so the time distribution it
learns from stays clean.

Run via `make tune-<target>` (the venv at .venv/ ships Optuna).
"""

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import optuna

REPO_ROOT  = Path(__file__).resolve().parents[1]
TEST_DIR   = REPO_ROOT / "build" / "test"

PER_TRIAL_TIMEOUT_S = 300

# Kill a trial subprocess once its wall time exceeds LEADER_KILL_MARGIN ×
# best-so-far. Pruning (instead of reporting a fake elapsed) keeps slow trials
# out of the sampler's likelihood model.
LEADER_KILL_MARGIN = 1.5
POLL_INTERVAL_S    = 0.05

# Trials run serially by default — each test holds a lot of state in RAM and
# stacking multiple in flight blows past available memory. Override with
# `N_JOBS=… make tune-…` once that's no longer a constraint. Single-threaded
# trials are also free to use all OpenMP cores, hence no OMP cap below.
N_JOBS    = int(os.environ.get("N_JOBS", 1))
TRIAL_ENV = {**os.environ}


@dataclass
class Target:
    binary:  Path
    filter:  str
    sample:  Callable[[optuna.Trial], dict]   # returns {flag: value} dict for this trial
    n_trials: int = 200


def _q_bits(depth: int) -> int:
    """Rough BGV/FIXEDAUTO ciphertext modulus bit budget: ~60 bits/limb x (depth + 1)."""
    return 60 * (depth + 1)


# TODO: Automate bounds, these are terrible
def _ell_bounds(log_b: int, depth: int) -> tuple[int, int]:
    q = _q_bits(depth)
    hi = max(1, q // log_b)
    lo = max(1, hi // 2)
    return lo, hi


def sample_rgsw(trial: optuna.Trial) -> dict:
    # depth is fixed at 2 inside the test (see test/src/rgsw.cpp); don't sweep.
    DEPTH = 2
    log_b = trial.suggest_int("gadget_base", 1, 60)
    lo, hi = _ell_bounds(log_b, DEPTH)
    ell    = trial.suggest_int("gadget_decomposition", lo, hi)
    scale  = trial.suggest_categorical("scaling_technique", ["FIXEDAUTO", "FIXEDMANUAL"])
    return {
        "gadget_base": log_b,
        "gadget_decomposition": ell,
        "scaling_technique": scale,
    }


def sample_main(trial: optuna.Trial) -> dict:
    # MultiHomPlacing currently runs at depth 8; sweep around that.
    depth  = trial.suggest_int("mult_depth", 4, 12)
    log_b  = trial.suggest_int("gadget_base", 1, 60)
    lo, hi = _ell_bounds(log_b, depth)
    ell    = trial.suggest_int("gadget_decomposition", lo, hi)
    scale  = trial.suggest_categorical("scaling_technique", ["FIXEDMANUAL", "FIXEDAUTO"])
    print(f"Decomposition in range [{lo}, {hi}]")
    return {
        "gadget_base": log_b,
        "gadget_decomposition": ell,
        "mult_depth": depth,
        "scaling_technique": scale,
    }


TARGETS: dict[str, Target] = {
    "rgsw": Target(
        binary  = TEST_DIR / "test-rgsw",
        filter  = "RGSW.b10",
        sample  = sample_rgsw,
    ),
    "main": Target(
        binary  = TEST_DIR / "test-main",
        filter  = "MultiHomPlacing.N2_1_1",
        sample  = sample_main,
    ),
}


def make_objective(target: Target):
    def objective(trial: optuna.Trial) -> float:
        flags = target.sample(trial)
        cmd = [str(target.binary)] + [f"--{k}={v}" for k, v in flags.items()] + [
            f"--gtest_filter={target.filter}",
            "--gtest_color=no",
        ]
        
        print(f"depth: {flags["mult_depth"]}, base: 2**{flags["gadget_base"]}, decomposition: {flags["gadget_decomposition"]}")

        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=TRIAL_ENV,
        )
        start = time.perf_counter()
        try:
            while True:
                try:
                    rc = proc.wait(timeout=POLL_INTERVAL_S)
                    break
                except subprocess.TimeoutExpired:
                    pass

                elapsed = time.perf_counter() - start
                if elapsed > PER_TRIAL_TIMEOUT_S:
                    raise optuna.TrialPruned()

                try:
                    leader = trial.study.best_value
                except ValueError:
                    leader = None
                if leader is not None and elapsed > leader * LEADER_KILL_MARGIN:
                    raise optuna.TrialPruned()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

        elapsed = time.perf_counter() - start
        if rc != 0:
            raise optuna.TrialPruned()
        return elapsed

    return objective


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in TARGETS:
        raise SystemExit(f"usage: {sys.argv[0]} <{'|'.join(TARGETS)}>")
    target = TARGETS[sys.argv[1]]

    if not target.binary.exists():
        raise SystemExit(f"test binary not found at {target.binary}; run `make test-{sys.argv[1]}` first")

    print(f"tuning {sys.argv[1]} ({target.filter}) with N_JOBS={N_JOBS}")
    study = optuna.create_study(direction="minimize")
    study.optimize(make_objective(target), n_trials=target.n_trials, n_jobs=N_JOBS)
    print(f"best params: {study.best_params}")
    print(f"best time: {study.best_value * 1000:.1f} ms")


if __name__ == "__main__":
    main()

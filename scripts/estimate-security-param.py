# !../.venv/bin/python
# Estimate security parameters for the main code using https://github.com/malb/lattice-estimator
# setup: ./scripts/setup.sh
# run:   make estimate
import argparse
import os
import tomllib
from dataclasses import dataclass
from math import isinf, log2
from pathlib import Path

from estimator import LWE
from estimator import nd as ND

# The same file the C++ factory reads (libs/utils/src/params.cpp). Keep in sync
# with the SPAR_PARAMS_FILE compile definition in CMakeLists.txt.
REPO_ROOT = Path(__file__).resolve().parent.parent
PARAMS_FILE = Path(os.environ.get("SPAR_PARAMS_FILE", REPO_ROOT / "params.toml"))


@dataclass(frozen=True)
class ParamSet:
    """A BGV parameter set from params.toml, as seen by the LWE estimator."""

    name: str
    N: int              # ring dimension -> LWE dimension
    logQ: int           # bits in the ciphertext modulus Q
    logP: int = 0       # bits in the GHS key-switching extension modulus P (0 = BV)
    # Always supplied by load_sets() from params.toml; the default only exists so
    # the field can follow logP, which has one.
    sigma: float = 3.19 # absolute stddev, 1-to-1 with OpenFHE SetStandardDeviation()
    limbs: int = 0      # RNS limbs in Q, i.e. `limbs` in params.toml

    @property
    def logQP(self) -> int:
        """Bits in the largest modulus an attacker sees (QP for GHS, Q for BV)."""
        return self.logQ + self.logP

    def lwe(self) -> LWE.Parameters:
        return LWE.Parameters(
            n=self.N,
            q=2**self.logQP,
            Xs=ND.UniformMod(3),  # ternary secret {-1,0,1}
            Xe=ND.DiscreteGaussian(stddev=self.sigma),
            m=2 * self.N,  # samples available to the attacker
            tag=self.name,
        )


def security(ps: ParamSet, full: bool = False) -> tuple[float, str]:
    """Cost in bits of the cheapest attack, and which attack it is."""
    # These are slow and never win unless sigma is << 3.19
    skip_attacks = ("arora-gb", "bkw", "bdd_mitm_hybrid")
    if full:
        results = LWE.estimate(ps.lwe(), quiet=True, jobs=6, deny_list=skip_attacks)
    else:
        results = LWE.estimate.rough(ps.lwe(), quiet=True, jobs=6)
    attack, cost = min(results.items(), key=lambda kv: kv[1]["rop"])
    return log2(float(cost["rop"])), attack


def load_sets(path: Path, force_hybrid: bool = False) -> list[ParamSet]:
    """Read every set from params.toml.

    Derivations mirror Set::LogQ() and Set::Depth() in libs/utils/src/params.cpp:
        logQ = first_mod_size + (limbs - 1) * scaling_mod_size
        logP = logQ if scheme == "hybrid" else 0

    `limbs` is the TOTAL RNS limb count in both single-party and multiparty mode
    (multiparty spends two of them on 60-bit flooding primes), so logQ is
    mode-independent as long as scaling_mod_size stays at 60.
    """
    with path.open("rb") as fh:
        data = tomllib.load(fh)

    sets = []
    for name, s in data.items():
        if not isinstance(s, dict):
            continue
        limbs = s["limbs"]
        logQ = s["first_mod_size"] + (limbs - 1) * s["scaling_mod_size"]
        hybrid = force_hybrid or s.get("scheme", "bv").lower() == "hybrid"
        sets.append(ParamSet(
            name=name,
            N=s["ring_dim"],
            logQ=logQ,
            logP=logQ if hybrid else 0,
            sigma=s["standard_deviation"],
            limbs=limbs,
        ))
    return sets


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true",
                        help="run all attacks with the default cost model (slow); "
                             "default is the rough core-SVP estimate")
    parser.add_argument("--hybrid", action="store_true",
                        help="treat every set as hybrid/GHS, so the attacker sees QP with "
                             "|P| = |Q|; use this to check a bv set that is also exercised "
                             "through GenContextHybrid, as test/src/products.cpp does")
    parser.add_argument("--params", type=Path, default=PARAMS_FILE,
                        help=f"parameter file to read (default: {PARAMS_FILE})")
    args = parser.parse_args()

    for ps in load_sets(args.params, force_hybrid=args.hybrid):
        bits, attack = security(ps, full=args.full)
        cost = "out of estimator range" if isinf(bits) else f"{bits:6.1f} bits  ({attack})"
        print(f"{ps.name:10}  N=2^{log2(ps.N):<3.0f} k={ps.limbs:<2} logQP={ps.logQP:<4}  ->  {cost}")

# !../.venv/bin/python
# Estimate security parameters for the main code using https://github.com/malb/lattice-estimator
# setup: ./scripts/setup.sh
# run:   make estimate
import argparse
from dataclasses import dataclass
from math import isinf, log2

from estimator import LWE
from estimator import nd as ND

@dataclass(frozen=True)
class ParamSet:
    """A BGV parameter set (see shared/params.h) as seen by the LWE estimator."""

    name: str
    N: int              # ring dimension -> LWE dimension
    logQ: int           # bits in the ciphertext modulus Q
    logP: int = 0       # bits in the GHS key-switching extension modulus P (0 = BV)
    sigma: float = 3.19 # absolute stddev, 1-to-1 with OpenFHE SetStandardDeviation()

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
    estimate = LWE.estimate if full else LWE.estimate.rough
    results = estimate(ps.lwe(), quiet=True, jobs=6, deny_list=skip_attacks)
    attack, cost = min(results.items(), key=lambda kv: kv[1]["rop"])
    return log2(float(cost["rop"])), attack


PARAM_SETS = [
    # 339.6 bits
    # ParamSet("standard", N=2**14, logQ=180, sigma=3.19)

    # 131.5 bits
    # ParamSet("standard", N=2**14, logQ=420, sigma=3.19)

    # ???.? bits
    ParamSet("standard", N=2**14, logQ=355, sigma=3.19)

    # Old sets
    # # 120.0 bits
    # ParamSet("spar",   N=2**11, logQ=64,  sigma=2**(64-55)),
    # ParamSet("near",   N=2**11, logQ=64,  sigma=3.19),
    # # 112.0 bits
    # ParamSet("bv",     N=2**12, logQ=120, sigma=1.5),
    # ParamSet("hybrid", N=2**13, logQ=155, logP=155, sigma=3.19),
    # # 183.0 bits
    # ParamSet("ghs-lg", N=2**14, logQ=155, logP=155, sigma=3.19),
    # # 130.2 bits
    # ParamSet("ideal",  N=2**12, logQ=106, sigma=3.19),
]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true",
                        help="run all attacks with the default cost model (slow); "
                             "default is the rough core-SVP estimate")
    args = parser.parse_args()

    for ps in PARAM_SETS:
        bits, attack = security(ps, full=args.full)
        cost = "out of estimator range" if isinf(bits) else f"{bits:6.1f} bits  ({attack})"
        print(f"{ps.name:10}  N=2^{log2(ps.N):<3.0f} logQP={ps.logQP:<4}  ->  {cost}")

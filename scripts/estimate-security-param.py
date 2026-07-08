# https://github.com/malb/lattice-estimator
# setup: ./scripts/setup.sh
# run:   .venv/bin/python scripts/estimate-security-param.py [--full]
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


PARAM_SETS = [
    # spar::params::Small, 2 x 60-bit limbs
    ParamSet("small",     N=2**12, logQ=120, sigma=3.19),
    ParamSet("small-ghs", N=2**13, logQ=120, logP=120, sigma=3.19),
    # spar::params::Large, 60 + 55-bit limbs
    ParamSet("large",     N=2**14, logQ=115, sigma=2**(-50)),
    ParamSet("large-ghs", N=2**14, logQ=115, logP=115, sigma=2**(-50)),
]


def security(ps: ParamSet, full: bool = False) -> tuple[float, str]:
    """Cost in bits of the cheapest attack, and which attack it is."""
    estimate = LWE.estimate if full else LWE.estimate.rough
    results = estimate(ps.lwe(), quiet=True)
    attack, cost = min(results.items(), key=lambda kv: kv[1]["rop"])
    return log2(float(cost["rop"])), attack


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




# N     = 2**(12)         # ring dimension -> LWE dimension
# k     = 2               # number of RNS moduli
# bits  = 60              # bitlength of each RNS modulus

# logQ  = k*bits
# Q     = 2**logQ

# sigma = 2**(-56)*Q      # absolute standard deviation
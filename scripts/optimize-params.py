# Find the preferred BGV parameters that keep the rough security estimate
# above a floor, e.g. the smallest error stddev with >= 128-bit security.
#
# Every setting given on the command line is fixed; every setting left out
# becomes a variable and is pushed as far toward its preferred (cheaper, but
# less secure) end as the security floor allows.
#
# setup: ./scripts/setup.sh
# run:   .venv/bin/python scripts/optimize-params.py --logn 12 --logq 120
#        .venv/bin/python scripts/optimize-params.py --logq 240 --sigma -56 --ghs
import argparse
import sys
from dataclasses import dataclass
from math import isinf, log2
from typing import Sequence

from estimator import LWE
from estimator import nd as ND


@dataclass(frozen=True)
class Variable:
    """One tunable setting.

    `domain` is ordered from the most secure value to the most preferred one.
    Security is monotone along it, so optimizing a free variable means
    bisecting for the last value that still meets the security floor.
    """

    name: str
    help: str
    domain: Sequence[int]


# When several settings are free, they are optimized in this order.
VARIABLES = [
    Variable("sigma", "log2 of the relative error stddev sigma/Q, e.g. -56 (smaller preferred)",
             domain=range(-2, -257, -1)),
    Variable("logn", "log2 of the ring dimension, e.g. 12 (smaller preferred)",
             domain=range(17, 9, -1)),
    Variable("logq", "bits in the ciphertext modulus Q, e.g. 120 (larger preferred)",
             domain=range(20, 601)),
]


def security(logn: int, logq: int, sigma: int, ghs: bool) -> float:
    """Cost in bits of the cheapest attack (rough core-SVP estimate)."""
    logQP = 2 * logq if ghs else logq  # GHS keys live mod QP with |P| = |Q|
    params = LWE.Parameters(
        n=2**logn,
        q=2**logQP,
        Xs=ND.UniformMod(3),                            # ternary secret {-1,0,1}
        Xe=ND.DiscreteGaussian(stddev=2.0**(logq + sigma)),  # noise scales with Q, not QP
        m=2**(logn + 1),                                # samples available to the attacker
    )
    results = LWE.estimate.rough(params, quiet=True)
    return min(log2(float(cost["rop"])) for cost in results.values())


def bisect_preferred(feasible, domain: Sequence[int]) -> int | None:
    """Last value of `domain` (ordered most secure -> most preferred) that is
    still feasible, or None if even the most secure value is not."""
    domain = list(domain)
    if not feasible(domain[0]):
        return None
    if feasible(domain[-1]):
        return domain[-1]
    lo, hi = 0, len(domain) - 1  # invariant: lo feasible, hi not
    while hi - lo > 1:
        mid = (lo + hi) // 2
        lo, hi = (mid, hi) if feasible(domain[mid]) else (lo, mid)
    return domain[lo]


def fmt_bits(bits: float) -> str:
    return "inf" if isinf(bits) else f"{bits:.1f}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Optimize BGV parameters against the lattice estimator; "
                    "omitted settings are treated as variables to optimize.")
    for var in VARIABLES:
        parser.add_argument(f"--{var.name}", type=int, help=var.help)
    parser.add_argument("--ghs", action="store_true",
                        help="GHS/hybrid key switching: the attacker sees QP with |P| = |Q|")
    parser.add_argument("--target", type=int, default=128, help="security floor in bits (default 128)")
    args = parser.parse_args()

    assignment = {var.name: getattr(args, var.name) for var in VARIABLES}
    free = [var for var in VARIABLES if assignment[var.name] is None]
    for var in free:  # start every free variable at its most secure value
        assignment[var.name] = var.domain[0]

    for var in free:
        def feasible(value: int) -> bool:
            bits = security(**(assignment | {var.name: value}), ghs=args.ghs)
            print(f"  trying {var.name} = {value:4}  ->  {fmt_bits(bits)} bits")
            return bits >= args.target

        print(f"optimizing {var.name}:")
        best = bisect_preferred(feasible, var.domain)
        if best is None:
            sys.exit(f"no {var.name} in [{var.domain[0]}, {var.domain[-1]}] reaches "
                     f"{args.target} bits with {assignment | {var.name: None}}")
        assignment[var.name] = best

    bits = security(**assignment, ghs=args.ghs)
    log_abs_sigma = assignment["logq"] + assignment["sigma"]

    print()
    for var in VARIABLES:
        origin = "optimized" if var in free else "given"
        print(f"  {var.name:5} = {assignment[var.name]:4}  ({origin})")
    print(f"  ghs   = {args.ghs}")
    print(f"  security ≈ {fmt_bits(bits)} bits (rough estimate, target {args.target})")
    print(f"  absolute stddev = 2^{log_abs_sigma}"
          f"  ->  params.SetStandardDeviation(std::pow(2.0, {log_abs_sigma}));")

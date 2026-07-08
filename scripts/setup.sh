#!/usr/bin/env bash
# Set up .venv and the lattice estimator
#
# Ubuntu 24.04 ships no sagemath package, so SageMath is installed into the
# venv as pip wheels via passagemath (https://github.com/passagemath/passagemath),
# which provides `sage.all` — everything vendors/lattice-estimator needs.
# The estimator itself is put on the venv's path with a .pth file pointing at
# the submodule, so updating the submodule needs no reinstall.
#
# First run downloads ~1.5 GB of wheels.
#
# Usage:
#   ./scripts/setup.sh
#   .venv/bin/python scripts/estimate-security-param.py

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$REPO_ROOT/.venv"
ESTIMATOR="$REPO_ROOT/vendors/lattice-estimator"

if [ ! -f "$ESTIMATOR/pyproject.toml" ]; then
    echo "Fetching lattice-estimator submodule..."
    git -C "$REPO_ROOT" submodule update --init vendors/lattice-estimator
fi

if [ ! -x "$VENV/bin/python" ]; then
    echo "Creating $VENV..."
    python3 -m venv "$VENV"
fi

"$VENV/bin/pip" install --upgrade pip
"$VENV/bin/pip" install passagemath-standard

SITE_PACKAGES="$("$VENV/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
echo "$ESTIMATOR" > "$SITE_PACKAGES/lattice-estimator.pth"

echo "Running smoke test..."
"$VENV/bin/python" - <<'EOF'
from estimator import LWE, schemes
print(LWE.primal_usvp(schemes.Kyber512))
EOF

echo
echo "Setup complete. Run the estimate with:"
echo "  $VENV/bin/python $REPO_ROOT/scripts/estimate-security-param.py"

.PHONY: all build ci clean clean-build clean-cmake clean-openfhe help params test tune-rgsw

all: build

#########
# Build #
#########

# Build OpenFHE with CI flags (no benchmarks/tests/examples) and install to vendors/install
# TODO: https://github.com/openfheorg/openfhe-development/blob/main/docs/static_docs/Best_Performance.md
ci:
	@echo "Building OpenFHE (CI mode)..."
	@cmake -S vendors/openfhe-development \
	       -B vendors/openfhe-development/build \
	       -DBUILD_STATIC=ON \
	       -DBUILD_BENCHMARKS=OFF \
	       -DBUILD_UNITTESTS=OFF \
	       -DBUILD_EXAMPLES=OFF \
	       -DBUILD_EXTRAS=OFF \
		   -DCMAKE_BUILD_TYPE=Release \
	       -DCMAKE_INSTALL_PREFIX="$(CURDIR)/vendors/install"
	@cmake --build vendors/openfhe-development/build -j$(shell nproc)
	@cmake --install vendors/openfhe-development/build

# Build OpenFHE and link statically
build:
	@echo "Building OpenFHE as static library (local install)..."
	@cd vendors/openfhe-development && mkdir -p build && cd build && \
		cmake .. -DBUILD_STATIC=ON -DCMAKE_INSTALL_PREFIX=../../install && \
		make && make install -j$(shell nproc)
	@echo "Building project with static OpenFHE..."
	@mkdir -p build && cd build && cmake .. -DBUILD_STATIC=ON && make -j$(shell nproc)

# TODO: Build using vendored OpenFHE shared libraries (no sudo required)


#########
# Tests #
#########

_CMAKE = cd build && cmake .. -DBUILD_STATIC=ON -DNATIVE_SIZE=64

# Build and run all tests
test:
	@mkdir -p build && $(_CMAKE) && cmake --build . --target check -j$(shell nproc)

# Build and run a specific test:
#   make test-rgsw
#   make test-expand-rlwe
#   make test-algorithm-1
test-%:
	@mkdir -p build && $(_CMAKE) && cmake --build . --target run-test-$* -j$(shell nproc)

###################
# Parameter tuning #
####################

# Set up a venv with Optuna installed. Always re-checks pip + optuna so this
# can be re-run whenever requirements change.
params:
	@python3 -m venv .venv
	@.venv/bin/pip install --upgrade pip optuna
	@touch .venv/.params-stamp

# Stamp file lets tune-rgsw skip the pip step on repeat runs.
.venv/.params-stamp:
	@$(MAKE) params

# One-click tuning. Builds the matching test binary (without running the suite
# — that would happen via run-test-*), then hands the target name to the
# search script which decides per-target search space + filter.
#   make tune-rgsw   →  scripts/parameter-search.py rgsw
#   make tune-main   →  scripts/parameter-search.py main
tune-%: .venv/.params-stamp
	@mkdir -p build && $(_CMAKE) && cmake --build . --target test-$* -j$(shell nproc)
	@.venv/bin/python scripts/parameter-search.py $*

############
# Clean-up #
############

# Clean everything
clean: clean-cmake clean-build

# Remove build artifacts
clean-build:
	@echo "Cleaning project build..."
	@rm -rf build

# Clean CMake cache
clean-cmake:
	@echo "Removing CMake cache..."
	@rm -rf build/CMakeCache.txt


################
# Instructions #
################

help:
	@echo "Available targets:"
	@echo "  build              - Build OpenFHE (static) and link project against it"
	@echo "  test               - Build and run all tests"
	@echo "  test-<name>        - Build and run a specific test (e.g. make test-rgsw)"
	@echo "  params             - Set up the .venv used by parameter tuning"
	@echo "  tune-<name>        - Run Optuna against test-<name> (e.g. tune-rgsw, tune-main)"
	@echo "  clean              - Clean project build artifacts"
	@echo "  clean-openfhe      - Clean OpenFHE build artifacts"
	@echo "  help               - Show this help message"

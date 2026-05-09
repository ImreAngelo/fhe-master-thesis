.PHONY: all build openfhe openfhe-clean test test-% bench bench-% params tune-% latex clean clean-build clean-cmake help

all: build

#######################
# OpenFHE (optimized) #
#######################

# One canonical OpenFHE install used by every target.
# Built with full optimizations:
#   NATIVEOPT, OpenMP, tcmalloc, reduced-noise, static, NATIVE_SIZE=64, Release.
# Delete vendors/install to force a rebuild.
OPENFHE_STAMP := vendors/install/lib/OpenFHE/OpenFHEConfig.cmake
TCM_STAMP     := vendors/install/lib/libtcmalloc_static.a

openfhe: $(OPENFHE_STAMP) $(TCM_STAMP)

$(OPENFHE_STAMP) $(TCM_STAMP):
	@echo "Building OpenFHE with full optimizations..."
	@rm -rf vendors/openfhe-development/build vendors/install
	@cmake -S vendors/openfhe-development -B vendors/openfhe-development/build \
		-DCMAKE_BUILD_TYPE=Release \
		-DBUILD_STATIC=ON \
		-DBUILD_SHARED=OFF \
		-DBUILD_BENCHMARKS=OFF \
		-DBUILD_UNITTESTS=OFF \
		-DBUILD_EXAMPLES=OFF \
		-DBUILD_EXTRAS=OFF \
		-DWITH_NATIVEOPT=ON \
		-DWITH_OPENMP=ON \
		-DWITH_REDUCED_NOISE=ON \
		-DWITH_TCM=ON \
		-DNATIVE_SIZE=64 \
		-DCMAKE_INSTALL_PREFIX="$(CURDIR)/vendors/install"
	@cmake --build vendors/openfhe-development/build --target tcm -j$(shell nproc)
	@cmake --build vendors/openfhe-development/build -j$(shell nproc)
	@cmake --install vendors/openfhe-development/build
	@cd vendors/install/lib && \
		ln -sf libtcmalloc_minimal.a libtcmalloc_static.a && \
		ln -sf libtcmalloc_minimal.so libtcmalloc_static.so

openfhe-clean:
	@rm -rf vendors/install vendors/openfhe-development/build

###########
# Project #
###########

# Single Release build dir, configured with -O3 -march=native everywhere so
# tests and benchmarks observe identical codegen.
BUILDDIR := build

# Opt-in debug instrumentation for tests:  DEBUG=1 make test-<name>
# Toggles DEBUG_TIMING / DEBUG_LOGGING on core_lib (and, transitively, tests).
ifeq ($(DEBUG),1)
_DEBUG_FLAGS := -DENABLE_DEBUG_TIMING=ON -DENABLE_DEBUG_LOGGING=ON
else
_DEBUG_FLAGS := -DENABLE_DEBUG_TIMING=OFF -DENABLE_DEBUG_LOGGING=OFF
endif

_CONFIGURE = cmake -S . -B $(BUILDDIR) \
	-DBUILD_STATIC=ON \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_CXX_FLAGS_RELEASE="-O3 -DNDEBUG -march=native -mtune=native" \
	$(_DEBUG_FLAGS)

# Build whatever production binaries are registered in CMakeLists.txt.
build: openfhe
	@$(_CONFIGURE)
	@cmake --build $(BUILDDIR) -j$(shell nproc)

#########
# Tests #
#########

# Build and run all tests against the optimized OpenFHE.
test: openfhe
	@$(_CONFIGURE)
	@cmake --build $(BUILDDIR) --target check -j$(shell nproc)

# Build and run a specific test:  make test-rgsw
test-%: openfhe
	@$(_CONFIGURE)
	@cmake --build $(BUILDDIR) --target run-test-$* -j$(shell nproc)

##############
# Benchmarks #
##############

# Delegated to benchmark/Makefile, which uses the same $(BUILDDIR) and depends
# on the openfhe target above. See `make -C benchmark help`.
bench: openfhe
	@$(MAKE) -C benchmark run BUILDDIR="$(CURDIR)/$(BUILDDIR)" BENCH_FILTER='$(BENCH_FILTER)'

bench-%: openfhe
	@$(MAKE) -C benchmark $@ BUILDDIR="$(CURDIR)/$(BUILDDIR)"

#####################
# Parameter tuning #
####################

# Set up a venv with Optuna installed. Always re-checks pip + optuna so this
# can be re-run whenever requirements change.
params:
	@python3 -m venv .venv
	@.venv/bin/pip install --upgrade pip optuna
	@touch .venv/.params-stamp

.venv/.params-stamp:
	@$(MAKE) params

# One-click tuning. Builds the matching test binary, then hands the target
# name to the search script which decides per-target search space + filter.
#   make tune-rgsw  →  scripts/parameter-search.py rgsw
tune-%: openfhe .venv/.params-stamp
	@$(_CONFIGURE)
	@cmake --build $(BUILDDIR) --target test-$* -j$(shell nproc)
	@.venv/bin/python scripts/parameter-search.py $*

############
# Clean-up #
############

clean: clean-cmake clean-build

clean-build:
	@echo "Cleaning project build..."
	@rm -rf $(BUILDDIR)

clean-cmake:
	@echo "Removing CMake cache..."
	@rm -rf $(BUILDDIR)/CMakeCache.txt

################
# Latex Thesis #
################

latex:
	$(MAKE) -C docs/latex

################
# Instructions #
################

help:
	@echo "Available targets:"
	@echo "  openfhe            - Build the optimized OpenFHE install (idempotent)"
	@echo "  build              - Configure project + build registered binaries"
	@echo "  test               - Build and run all tests"
	@echo "  test-<name>        - Build and run a specific test (e.g. make test-rgsw)"
	@echo "                       Add DEBUG=1 to enable DEBUG_TIMER / DEBUG_PRINT output"
	@echo "  bench              - Build + run all benchmarks (delegates to benchmark/)"
	@echo "  bench-<name>       - Build a specific benchmark binary"
	@echo "  params             - Set up the .venv used by parameter tuning"
	@echo "  tune-<name>        - Run Optuna against test-<name>"
	@echo "  clean              - Clean project build artifacts"
	@echo "  help               - Show this help message"

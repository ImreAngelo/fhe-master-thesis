.PHONY: all build openfhe openfhe-clean test test-% bench bench-% bench-full-write params format format-check data clean clean-build clean-cmake help

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

# Build whatever production binaries are registered in CMakeLists.txt
build: openfhe
	@$(_CONFIGURE)
	@cmake --build $(BUILDDIR) -j$(shell nproc)

####################
# Parameter Tuning #
####################

estimate:
	@echo "Estimating security parameters with lattice-estimator..."
	@./.venv/bin/python scripts/estimate-security-param.py --full

#########
# Tests #
#########

# DEBUG=1 make test-% TEST_OMP_THREADS=X
TEST_OMP_THREADS ?= 12

# Build and run all tests against the optimized OpenFHE build
test: openfhe
	@$(_CONFIGURE)
	@OMP_NUM_THREADS=$(TEST_OMP_THREADS) cmake --build $(BUILDDIR) --target check -j$(shell nproc)

# Build and run a specific test:  make test-rgsw
test-%: openfhe
	@$(_CONFIGURE)
	@OMP_NUM_THREADS=$(TEST_OMP_THREADS) cmake --build $(BUILDDIR) --target run-test-$* -j$(shell nproc)

##############
# Benchmarks #
##############

# Run all benchmarks
bench: openfhe
	@$(MAKE) -C benchmark run BUILDDIR="$(CURDIR)/$(BUILDDIR)" BENCH_FILTER='$(BENCH_FILTER)'

# Full-pipeline benchmark with all N server writes per iteration. The default
# bench-full does a single write and reports its actual time.
bench-full-write: openfhe
	@FULL_WRITE=1 $(MAKE) -C benchmark run BUILDDIR="$(CURDIR)/$(BUILDDIR)" BENCH_NAMES='full' BENCH_FILTER='$(BENCH_FILTER)'

# Run specific benchmark:  make bench-rgsw
bench-%: openfhe
	@$(MAKE) -C benchmark run BUILDDIR="$(CURDIR)/$(BUILDDIR)" BENCH_NAMES='$*' BENCH_FILTER='$(BENCH_FILTER)'

###############
# Thesis data #
###############

# Copy fresh results into the thesis, preserving any subdirectory structure:
#   test/results/<path>.csv        -> docs/latex/Data/Noise/<path>.csv
#   build/results-<path>.json      -> docs/latex/Data/Times/<path>.json
# Sources are gitignored run outputs and are left in place; destinations are
# tracked by git, so missing sources are skipped silently (nothing to publish).
DATADIR := docs/latex/Data
NOISEDIR := $(DATADIR)/Noise
TIMESDIR := $(DATADIR)/Times

data:
	@copied=0; \
	mkdir -p "$(NOISEDIR)" "$(TIMESDIR)"; \
	for f in $$(find test/results -type f -name '*.csv' 2>/dev/null); do \
		[ -s "$$f" ] || { echo "  SKIP $$f (empty)"; continue; }; \
		dst="$(NOISEDIR)/$${f#test/results/}"; \
		mkdir -p "$$(dirname "$$dst")"; \
		cp "$$f" "$$dst" && echo "  $$f -> $$dst" && copied=$$((copied+1)); \
	done; \
	for f in $$(find $(BUILDDIR) -type f -name 'results-*.json' 2>/dev/null); do \
		[ -s "$$f" ] || { echo "  SKIP $$f (empty)"; continue; }; \
		rel="$${f#$(BUILDDIR)/}"; \
		dst="$(TIMESDIR)/$$(dirname "$$rel")/$$(basename "$$rel" | sed 's/^results-//')"; \
		dst="$$(echo "$$dst" | sed 's#/\./#/#')"; \
		mkdir -p "$$(dirname "$$dst")"; \
		cp "$$f" "$$dst" && echo "  $$f -> $$dst" && copied=$$((copied+1)); \
	done; \
	echo "Copied $$copied file(s) into $(DATADIR)"

##############
# Formatting #
##############

# All hand-written C++ sources/headers. vendors/ and build/ are excluded
CLANG_FORMAT ?= clang-format
FORMAT_FILES := $(shell find libs benchmark test -type f \( -name '*.cpp' -o -name '*.h' \))

# Rewrite files in place to match .clang-format
format:
	@echo "Formatting $(words $(FORMAT_FILES)) files..."
	@$(CLANG_FORMAT) -i $(FORMAT_FILES)

# Report files that are not formatted, without modifying them (exit 1 if any)
format-check:
	@$(CLANG_FORMAT) --dry-run --Werror $(FORMAT_FILES)

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
# Instructions #
################

help:
	@echo "Available targets:"
	@echo "  openfhe            - Build the optimized OpenFHE install (idempotent)"
	@echo "  build              - Configure project + build registered binaries"
	@echo "  test               - Build and run all tests"
	@echo "  test-<name>        - Build and run a specific test (e.g. make test-rgsw)"
	@echo "                       Add DEBUG=1 to enable DEBUG_TIMER / DEBUG_PRINT output"
	@echo "                       TEST_OMP_THREADS=<n> sets OMP_NUM_THREADS (default: 12)"
	@echo "  bench              - Build + run all benchmarks (delegates to benchmark/)"
	@echo "  bench-<name>       - Build + run a specific benchmark (e.g. bench-rgsw)"
	@echo "                       bench-full does 1 server write and reports its actual time"
	@echo "  bench-full-write   - bench-full with all N server writes run for real"
	@echo "  data               - Copy test CSVs into Data/Noise, benchmark JSONs into Data/Times"
	@echo "  format             - Run clang-format -i over libs, benchmark and test"
	@echo "  format-check       - Check formatting without modifying (fails if dirty)"
	@echo "  params             - Set up the .venv used by parameter tuning"
	@echo "  tune-<name>        - Run Optuna against test-<name>"
	@echo "  clean              - Clean project build artifacts"
	@echo "  help               - Show this help message"

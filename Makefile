.PHONY: all build openfhe openfhe-clean test test-% bench bench-% params format format-check data clean clean-build clean-cmake help

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

# Build and run all tests against the optimized OpenFHE build
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

# Run all benchmarks
bench: openfhe
	@$(MAKE) -C benchmark run BUILDDIR="$(CURDIR)/$(BUILDDIR)" BENCH_FILTER='$(BENCH_FILTER)'

# Run specific benchmark:  make bench-rgsw
bench-%: openfhe
	@$(MAKE) -C benchmark run BUILDDIR="$(CURDIR)/$(BUILDDIR)" BENCH_NAMES='$*' BENCH_FILTER='$(BENCH_FILTER)'

###############
# Thesis data #
###############

# Move fresh results into the thesis:
#   build/results-<name>.json  -> docs/latex/Data/<name>.json
#   test/results/<chain>.csv   -> docs/latex/Data/{External,Internal}Product/<impl>.csv
# Sources are gitignored run outputs; destinations are tracked by git, so
# missing sources are skipped silently (nothing new to publish).
DATADIR := docs/latex/Data

# test/results/<src>.csv -> $(DATADIR)/<dst>.csv (names match the plot inputs
# under Figures/Plots/, hence Hybrid -> ghs)
CSV_MAP := \
	external_chain_BV_Small:ExternalProduct/bv-small \
	external_chain_BV_Large:ExternalProduct/bv-large \
	external_chain_Hybrid:ExternalProduct/ghs-small \
	external_chain_Hybrid_large:ExternalProduct/ghs-large \
	internal_chain_BV_Small:InternalProduct/bv-small \
	internal_chain_BV_Large:InternalProduct/bv-large \
	internal_chain_Hybrid:InternalProduct/ghs-small \
	internal_chain_Hybrid_large:InternalProduct/ghs-large

data:
	@moved=0; \
	for f in $(BUILDDIR)/results-*.json; do \
		[ -f "$$f" ] || continue; \
		[ -s "$$f" ] || { echo "  SKIP $$f (empty)"; continue; }; \
		dst="$(DATADIR)/$$(basename $$f | sed 's/^results-//')"; \
		mv "$$f" "$$dst" && echo "  $$f -> $$dst" && moved=$$((moved+1)); \
	done; \
	for m in $(CSV_MAP); do \
		src="test/results/$${m%%:*}.csv"; dst="$(DATADIR)/$${m##*:}.csv"; \
		[ -f "$$src" ] || continue; \
		[ -s "$$src" ] || { echo "  SKIP $$src (empty)"; continue; }; \
		mkdir -p "$$(dirname "$$dst")"; \
		mv "$$src" "$$dst" && echo "  $$src -> $$dst" && moved=$$((moved+1)); \
	done; \
	echo "Moved $$moved file(s) into $(DATADIR)"

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
	@echo "  bench              - Build + run all benchmarks (delegates to benchmark/)"
	@echo "  bench-<name>       - Build + run a specific benchmark (e.g. bench-rgsw)"
	@echo "  data               - Move benchmark JSONs + test CSVs into docs/latex/Data"
	@echo "  format             - Run clang-format -i over libs, benchmark and test"
	@echo "  format-check       - Check formatting without modifying (fails if dirty)"
	@echo "  params             - Set up the .venv used by parameter tuning"
	@echo "  tune-<name>        - Run Optuna against test-<name>"
	@echo "  clean              - Clean project build artifacts"
	@echo "  help               - Show this help message"

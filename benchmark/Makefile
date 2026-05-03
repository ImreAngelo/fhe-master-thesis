.PHONY: all run build help clean

# Run from the benchmark/ subdir; project root is one level up.
ROOT     := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
BUILDDIR := $(ROOT)/.bench

# Auto-discovered: every benchmark/src/<name>.cpp registered in CMakeLists.txt
# lives at benchmark/src/<name>.cpp on disk. Glob picks them up so a new file
# is included by `make bench` without touching this Makefile.
ALL_BENCH_NAMES := $(patsubst $(ROOT)/benchmark/src/%.cpp,%,$(wildcard $(ROOT)/benchmark/src/*.cpp))

# Defaults — override per invocation, e.g.
#   make run BENCH_NAMES=rgsw                 # only one
#   make run BENCH_FILTER=ExternalProduct
#   make run BENCH_REPETITIONS=10
BENCH_NAMES       ?= $(ALL_BENCH_NAMES)
BENCH_FILTER      ?= .*
BENCH_TIME_UNIT   ?= ms
BENCH_REPETITIONS ?= 10

# Per-binary flags — BENCH_OUT is per-name so the JSON files don't collide.
bench_flags = \
	--benchmark_filter="$(BENCH_FILTER)" \
	--benchmark_time_unit=$(BENCH_TIME_UNIT) \
	--benchmark_repetitions=$(BENCH_REPETITIONS) \
	--benchmark_report_aggregates_only=true \
	--benchmark_out_format=json \
	--benchmark_out="$(BUILDDIR)/results-$(1).json" \
	--benchmark_color=yes

all: run

# Build the optimized OpenFHE install if not already present, then build every
# benchmark binary in $(BENCH_NAMES) into $(BUILDDIR) with -O3 -march=native
# and run them sequentially.
run: build
	@for name in $(BENCH_NAMES); do \
		echo ""; \
		echo "▶ bench-$$name (filter=$(BENCH_FILTER))"; \
		$(BUILDDIR)/benchmark/bench-$$name $(call bench_flags,$$name) || exit $$?; \
		echo "  JSON: $(BUILDDIR)/results-$$name.json"; \
	done

# Build a specific benchmark binary without running. Pattern target so
# `make bench-rgsw` (delegated from the root) reaches us as `bench-rgsw` here.
bench-%: openfhe-optimized
	@mkdir -p $(BUILDDIR) && cd $(BUILDDIR) && cmake $(ROOT) \
		-DBUILD_STATIC=ON \
		-DNATIVE_SIZE=64 \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_CXX_FLAGS_RELEASE="-O3 -DNDEBUG -march=native -mtune=native"
	@cmake --build $(BUILDDIR) --target bench-$* -j$(shell nproc)

build: $(addprefix bench-,$(BENCH_NAMES))

# Build OpenFHE with full optimizations (NATIVEOPT, OpenMP, tcmalloc, reduced
# noise) into vendors/install. Skipped if already installed — delete
# $(ROOT)/vendors/install to force a rebuild.
openfhe-optimized:
	@if [ ! -f $(ROOT)/vendors/install/lib/OpenFHE/OpenFHEConfig.cmake ] || \
	    [ ! -f $(ROOT)/vendors/install/lib/libtcmalloc_static.a ]; then \
		echo "Building OpenFHE with full optimizations..."; \
		rm -rf $(ROOT)/vendors/openfhe-development/build $(ROOT)/vendors/install; \
		cmake -S $(ROOT)/vendors/openfhe-development -B $(ROOT)/vendors/openfhe-development/build \
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
			-DCMAKE_INSTALL_PREFIX="$(ROOT)/vendors/install"; \
		cmake --build $(ROOT)/vendors/openfhe-development/build --target tcm -j$(shell nproc); \
		cmake --build $(ROOT)/vendors/openfhe-development/build -j$(shell nproc); \
		cmake --install $(ROOT)/vendors/openfhe-development/build; \
		cd $(ROOT)/vendors/install/lib && \
			ln -sf libtcmalloc_minimal.a libtcmalloc_static.a && \
			ln -sf libtcmalloc_minimal.so libtcmalloc_static.so; \
	fi

clean:
	@rm -rf $(BUILDDIR)

help:
	@echo "Benchmark targets (run from project root via 'make bench' or here directly):"
	@echo "  run                - Build optimized + run all benchmarks in BENCH_NAMES"
	@echo "  bench-<name>       - Build a specific benchmark binary (e.g. bench-rgsw)"
	@echo "  openfhe-optimized  - Build the optimized OpenFHE install (idempotent)"
	@echo "  clean              - Remove the .bench/ build dir"
	@echo ""
	@echo "Variables:"
	@echo "  BENCH_NAMES=<list>    space-separated stems to run (default: all in src/)"
	@echo "                        currently auto-discovered: $(ALL_BENCH_NAMES)"
	@echo "  BENCH_FILTER=<regex>  --benchmark_filter (default: .*)"
	@echo "  BENCH_TIME_UNIT=<u>   --benchmark_time_unit (default: ms)"
	@echo "  BENCH_REPETITIONS=<n> --benchmark_repetitions (default: 5)"

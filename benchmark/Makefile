.PHONY: all run build help clean

# Run from the benchmark/ subdir; project root is one level up.
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)

# Shared with the root Makefile. Override with `make -C benchmark BUILDDIR=...`
# when invoking from outside; the root delegates already pass it through.
BUILDDIR ?= $(ROOT)/build

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

# OpenFHE's keyswitch uses a nested `#pragma omp parallel for` over a small
# (sizeQlP ≈ 6–7) inner loop, so at our parameters (depth=3, dnum=2) thread
# spawn cost dominates and multi-threaded runs are *slower* than single-thread.
# Lock the env down for reproducible timings; override with BENCH_OMP_THREADS.
BENCH_OMP_THREADS ?= 1

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

# Build every benchmark binary in $(BENCH_NAMES) into $(BUILDDIR), then run them
# sequentially with OMP pinned (see BENCH_OMP_THREADS above).
run: build
	@for name in $(BENCH_NAMES); do \
		echo ""; \
		echo "▶ bench-$$name (filter=$(BENCH_FILTER), OMP_NUM_THREADS=$(BENCH_OMP_THREADS))"; \
		OMP_NUM_THREADS=$(BENCH_OMP_THREADS) $(BUILDDIR)/benchmark/bench-$$name $(call bench_flags,$$name) || exit $$?; \
		echo "  JSON: $(BUILDDIR)/results-$$name.json"; \
	done

# Build a specific benchmark binary without running. The OpenFHE install +
# project configuration are owned by the root Makefile — we just drive the
# target build here.
bench-%:
	@$(MAKE) -C $(ROOT) openfhe
	@cmake -S $(ROOT) -B $(BUILDDIR) \
		-DBUILD_STATIC=ON \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_CXX_FLAGS_RELEASE="-O3 -DNDEBUG -march=native -mtune=native"
	@cmake --build $(BUILDDIR) --target bench-$* -j$(shell nproc)

build: $(addprefix bench-,$(BENCH_NAMES))

clean:
	@rm -rf $(BUILDDIR)

help:
	@echo "Benchmark targets (run from project root via 'make bench' or here directly):"
	@echo "  run                - Build + run all benchmarks in BENCH_NAMES"
	@echo "  bench-<name>       - Build a specific benchmark binary (e.g. bench-rgsw)"
	@echo "  clean              - Remove the build dir"
	@echo ""
	@echo "Variables:"
	@echo "  BENCH_NAMES=<list>      space-separated stems to run (default: all in src/)"
	@echo "                          currently auto-discovered: $(ALL_BENCH_NAMES)"
	@echo "  BENCH_FILTER=<regex>    --benchmark_filter (default: .*)"
	@echo "  BENCH_TIME_UNIT=<u>     --benchmark_time_unit (default: ms)"
	@echo "  BENCH_REPETITIONS=<n>   --benchmark_repetitions (default: 10)"
	@echo "  BENCH_OMP_THREADS=<n>   OMP_NUM_THREADS for the run (default: 1)"

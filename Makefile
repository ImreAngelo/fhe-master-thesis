.PHONY: all build ci clean clean-build clean-cmake clean-openfhe help test

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

# Build OpenFHE locally and link statically (no -static flag, just static archives)
build:
	@echo "Building OpenFHE as static library (local install)..."
	@cd vendors/openfhe-development && mkdir -p build && cd build && \
		cmake .. -DBUILD_STATIC=ON -DCMAKE_INSTALL_PREFIX=../../install && \
		make && make install -j$(shell nproc)
	@echo "Building project with static OpenFHE..."
	@mkdir -p build && cd build && cmake .. -DBUILD_STATIC=ON && make -j$(shell nproc)

# Build using vendored OpenFHE shared libraries (no sudo required)
# build-dynamic:
# 	@echo "Building OpenFHE locally (shared libraries)..."
# 	@cd vendors/openfhe-development && mkdir -p build && cd build && cmake .. && make -j$(shell nproc)
# 	@echo "Building project with shared OpenFHE..."
# 	@mkdir -p build && cd build && cmake .. -DBUILD_STATIC=OFF && make -j$(shell nproc)

# Future production binaries — uncomment when add_executable() exists in CMakeLists.txt
# app client server:
# 	@mkdir -p build && cd build && cmake .. -DBUILD_STATIC=ON && cmake --build . --target $@ -j$(shell nproc)


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

# Why would you need this..? Rebuild time is very long! 
# clean-openfhe:
# 	@echo "Cleaning OpenFHE build..."
# 	@rm -rf vendors/openfhe-development/build 
# 	@rm -rf vendors/install


################
# Instructions #
################

help:
	@echo "Available targets:"
	@echo "  build              - Build OpenFHE (static) and link project against it"
	@echo "  test               - Build and run all tests"
	@echo "  test-<name>        - Build and run a specific test (e.g. make test-rgsw)"
	@echo "  clean              - Clean project build artifacts"
	@echo "  clean-openfhe      - Clean OpenFHE build artifacts"
	@echo "  help               - Show this help message"

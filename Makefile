.PHONY: all build build-dynamic clean clean-openfhe help

# Default target
all: build

############
# Building #
############

# Build OpenFHE locally and link statically (no -static flag, just static archives)
build:
	@echo "Building OpenFHE locally (static archives)..."
	@cd vendors/openfhe-development && mkdir -p build && cd build && cmake .. -DBUILD_STATIC=ON && make -j$(shell nproc)
	@echo "Building project with static OpenFHE..."
	@mkdir -p build && cd build && cmake .. -DBUILD_STATIC=ON && make -j$(shell nproc)

# Build using vendored OpenFHE shared libraries (no sudo required)
build-dynamic:
	@echo "Building OpenFHE locally (shared libraries)..."
	@cd vendors/openfhe-development && mkdir -p build && cd build && cmake .. && make -j$(shell nproc)
	@echo "Building project with shared OpenFHE..."
	@mkdir -p build && cd build && cmake .. -DBUILD_STATIC=OFF && make -j$(shell nproc)

# 
run: 
	@./build/test

############
# Clean-up #
############

# Clean everything
clean-all: clean clean-openfhe

# Clean OpenFHE build
clean-openfhe:
	@echo "Cleaning OpenFHE build..."
	@rm -rf vendors/openfhe-development/build

# Clean build artifacts
clean-build:
	@echo "Cleaning project build..."
	@rm -rf build


################
# Instructions #
################

help:
	@echo "Available targets:"
	@echo "  build          - Build OpenFHE vendored (static archives) and link project against them"
	@echo "  build-dynamic  - Build OpenFHE vendored (shared libs) and link project dynamically"
	@echo "  clean          - Clean project build artifacts"
	@echo "  clean-openfhe  - Clean OpenFHE build artifacts"
	@echo "  clean-all      - Clean all build artifacts"
	@echo "  help           - Show this help message"

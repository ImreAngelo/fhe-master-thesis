# Makefile for building the project with OpenFHE options

.PHONY: all build build-dynamic clean clean-openfhe help

# Default target
all: build

# Build OpenFHE locally and link statically
build:
	@echo "Building OpenFHE locally..."
	@cd vendors/openfhe-development && mkdir -p build && cd build && cmake .. -DBUILD_STATIC=ON && make -j$(shell nproc)
	@echo "Building project with local OpenFHE..."
	@mkdir -p build && cd build && cmake .. -DBUILD_STATIC=ON && make -j$(shell nproc)

# Install OpenFHE system-wide and link dynamically
# For faster and smaller build on systems that already have OpenFHE installed
build-dynamic:
	@echo "Installing OpenFHE system-wide..."
	@cd vendors/openfhe-development && mkdir -p build && cd build && cmake .. && make -j$(shell nproc) && sudo make install
	@echo "Building project with system OpenFHE..."
	@mkdir -p build && cd build && cmake .. && make -j$(shell nproc)

# Windows
build-win:
	@echo "TODO: Not implemented..."

# Clean build artifacts
clean:
	@echo "Cleaning project build..."
	@rm -rf build

# Clean OpenFHE build
clean-openfhe:
	@echo "Cleaning OpenFHE build..."
	@rm -rf vendors/openfhe-development/build

# Clean everything
clean-all: clean clean-openfhe

# Help target
help:
	@echo "Available targets:"
	@echo "  build        	- Build OpenFHE locally and link project statically"
	@echo "  build-dynamic 	- Install OpenFHE system-wide and link project dynamically"
	@echo "  clean        	- Clean project build artifacts"
	@echo "  clean-openfhe 	- Clean OpenFHE build artifacts"
	@echo "  clean-all    	- Clean all build artifacts"
	@echo "  help         	- Show this help message"
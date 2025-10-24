# QyberSafe Makefile
# Simplified build interface for the QyberSafe library

.PHONY: all clean install test benchmark docs help format lint

# Default target
all: build

# Build the library
build:
	@echo "Building QyberSafe..."
	mkdir -p build
	cd build && cmake .. -DCMAKE_BUILD_TYPE=Release
	cd build && make -j$(nproc)

# Build debug version
debug:
	@echo "Building QyberSafe (Debug)..."
	mkdir -p build-debug
	cd build-debug && cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
	cd build-debug && make -j$(nproc)

# Run tests
test: build
	@echo "Running tests..."
	cd build && ctest --output-on-failure --parallel

# Run tests with memory checking
test-memory: debug
	@echo "Running tests with Valgrind..."
	cd build-debug && valgrind --leak-check=full --error-exitcode=1 ./tests/qybersafe_tests

# Run benchmarks
benchmark: build
	@echo "Running benchmarks..."
	cd build && make run_benchmarks || echo "No benchmark target found"

# Install library
install: build
	@echo "Installing QyberSafe..."
	cd build && sudo make install

# Build Python bindings
python-bindings:
	@echo "Building Python bindings..."
	cd python && python setup.py build_ext --inplace

# Test Python bindings
test-python: python-bindings
	@echo "Testing Python bindings..."
	cd python && python -m pytest -v

# Generate documentation
docs:
	@echo "Generating documentation..."
	cd build && make docs || doxygen Doxyfile || echo "Documentation generation failed"

# Format code
format:
	@echo "Formatting code..."
	find src -name "*.cpp" -o -name "*.h" | xargs clang-format -i
	find python -name "*.py" | xargs black

# Lint code
lint:
	@echo "Linting C++ code..."
	cppcheck --enable=all --inconclusive src/
	@echo "Linting Python code..."
	cd python && flake8 qybersafe/ || echo "Python linting not available"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf build build-debug
	cd python && python setup.py clean --all || true
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + || true

# Clean everything including dependencies
distclean: clean
	@echo "Cleaning all generated files..."
	rm -rf install docs/html

# Install development dependencies
setup-dev:
	@echo "Setting up development environment..."
	sudo apt-get update
	sudo apt-get install -y cmake build-essential libssl-dev libgtest-dev libgmock-dev
	sudo apt-get install -y clang-format cppcheck valgrind
	pip install pybind11 pytest black flake8

# Run full CI pipeline locally
ci: setup-dev build test test-python lint

# Package for distribution
package: build
	@echo "Creating packages..."
	cd build && cpack

# Show help
help:
	@echo "QyberSafe Build System"
	@echo "======================="
	@echo ""
	@echo "Targets:"
	@echo "  build          - Build the library (Release mode)"
	@echo "  debug          - Build the library (Debug mode)"
	@echo "  test           - Run C++ tests"
	@echo "  test-memory    - Run tests with Valgrind"
	@echo "  benchmark      - Run performance benchmarks"
	@echo "  install        - Install the library system-wide"
	@echo "  python-bindings - Build Python bindings"
	@echo "  test-python    - Test Python bindings"
	@echo "  docs           - Generate documentation"
	@echo "  format         - Format source code"
	@echo "  lint           - Lint source code"
	@echo "  clean          - Clean build artifacts"
	@echo "  distclean      - Clean all generated files"
	@echo "  setup-dev      - Install development dependencies"
	@echo "  ci             - Run full CI pipeline locally"
	@echo "  package        - Create distribution packages"
	@echo "  help           - Show this help message"
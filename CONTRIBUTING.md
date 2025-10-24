# Contributing to QyberSafe

Thank you for your interest in contributing to QyberSafe! This document provides guidelines for contributing to the project.

## Getting Started

### Prerequisites

- C++17 compatible compiler (GCC 7+, Clang 6+, MSVC 2017+)
- CMake 3.16+
- OpenSSL development libraries
- Python 3.7+ (for Python bindings)
- Git

### Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Nathandona/qybersafe.git
   cd qybersafe
   ```

2. **Install dependencies:**
   ```bash
   make setup-dev
   ```

3. **Build the project:**
   ```bash
   make build
   ```

4. **Run tests:**
   ```bash
   make test
   ```

## Development Workflow

### Using Docker

For a consistent development environment, use Docker:

```bash
# Start development container
docker-compose run --rm qybersafe-dev

# Inside the container, run commands like:
make build
make test
make format
```

### Local Development

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes:**
   - Write clean, well-commented code
   - Follow existing code style
   - Add tests for new functionality

3. **Run the test suite:**
   ```bash
   make test          # Run C++ tests
   make test-python   # Run Python tests
   ```

4. **Format your code:**
   ```bash
   make format        # Auto-format code
   ```

5. **Lint your code:**
   ```bash
   make lint          # Run linting tools
   ```

## Code Style Guide

### C++ Guidelines

- Follow Google C++ Style Guide
- Use 4 spaces for indentation (no tabs)
- Maximum line length: 80 characters
- Use descriptive variable and function names
- Include proper documentation in headers

### Python Guidelines

- Follow PEP 8 style guide
- Use 4 spaces for indentation
- Maximum line length: 88 characters
- Include type hints where appropriate
- Write docstrings for public functions

## Testing

### C++ Tests

- Write unit tests using Google Test framework
- Aim for high test coverage (>90%)
- Test both success and failure cases
- Include performance benchmarks for critical functions

### Python Tests

- Write tests using pytest
- Test both C++ bindings and pure Python functionality
- Include integration tests

## Documentation

- Document all public APIs in header files
- Include usage examples in documentation
- Update README.md when adding new features
- Generate Doxygen documentation for C++ API

## Security Considerations

- **Never commit secrets, keys, or test vectors**
- Use secure random number generation
- Follow secure coding practices
- Perform security reviews on cryptographic code
- Test for side-channel vulnerabilities

## Submitting Changes

1. **Create a pull request:**
   - Provide a clear title and description
   - Reference relevant issues
   - Include screenshots for UI changes

2. **Ensure PR passes CI:**
   - All tests must pass
   - Code must build on all supported platforms
   - Documentation must build successfully

3. **Code review:**
   - Address reviewer feedback promptly
   - Be responsive to requests for changes
   - Keep discussions professional and constructive

## Issue Reporting

### Bug Reports

- Use the bug report template
- Include detailed reproduction steps
- Provide system information (OS, compiler, etc.)
- Attach relevant logs or output

### Feature Requests

- Use the feature request template
- Describe the use case clearly
- Consider implementation complexity
- Suggest API design if possible

## Development Commands

```bash
# Build and test
make build          # Build library
make debug          # Build debug version
make test           # Run tests
make test-memory    # Run with Valgrind
make benchmark      # Run benchmarks

# Code quality
make format         # Format code
make lint           # Run linting tools

# Documentation
make docs           # Generate documentation

# Python
make python-bindings  # Build Python bindings
make test-python      # Test Python bindings

# Cleanup
make clean          # Clean build artifacts
make distclean      # Clean everything
```

## Release Process

1. Update version numbers
2. Update CHANGELOG.md
3. Create release tag
4. Build release binaries
5. Test cross-platform compatibility
6. Update documentation
7. Publish release

## Security Vulnerability Reporting

For security vulnerabilities, please email: security@qybersafe.io

Do not open public issues for security vulnerabilities.

## Getting Help

- Check the [documentation](docs/)
- Search existing issues
- Join our discussion forums
- Reach out to maintainers

## Code of Conduct

Please be respectful and professional in all interactions. See CODE_OF_CONDUCT.md for details.

Thank you for contributing to QyberSafe! 🚀
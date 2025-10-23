# Makefile for autograph-pls

# Build variables
BINARY_NAME=autograph-pls
BUILD_DIR=build

.PHONY: all build clean

# Default target
all: build

# Build the binary for Linux AMD64
build:
	@echo "Building ${BINARY_NAME} for Linux/AMD64..."
	@mkdir -p ${BUILD_DIR}
	GOOS=linux GOARCH=amd64 go build -o ${BUILD_DIR}/${BINARY_NAME}-linux-amd64 .
	@echo "Build complete: ${BUILD_DIR}/${BINARY_NAME}-linux-amd64"

# Utility targets
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf ${BUILD_DIR}


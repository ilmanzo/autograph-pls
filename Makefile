# Makefile for autograph-pls

# Build variables
BINARY_NAME=autograph-pls
VERSION?=dev
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-ldflags "-w -s -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}"

# Go variables
GOOS?=$(shell go env GOOS)
GOARCH?=$(shell go env GOARCH)
GOMOD=$(shell test -f "go.mod" && echo "-mod=readonly")

# Directories
BUILD_DIR=build
COVERAGE_DIR=coverage
TEST_RESULTS_DIR=test-results

# Colors for output
GREEN=\033[0;32m
YELLOW=\033[1;33m
RED=\033[0;31m
NC=\033[0m # No Color

.PHONY: all build clean test test-unit test-integration test-good test-bad coverage lint format vet check help install deps

# Default target
all: clean deps check build test

help: ## Display this help screen
	@echo "autograph-pls - ASN.1 Signature Parser"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Build targets
build: ## Build the binary
	@echo "${GREEN}Building ${BINARY_NAME}...${NC}"
	@mkdir -p ${BUILD_DIR}
	go build ${GOMOD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}
	@echo "${GREEN}Build complete: ${BUILD_DIR}/${BINARY_NAME}${NC}"

build-all: ## Build for all supported platforms
	@echo "${GREEN}Building for all platforms...${NC}"
	@mkdir -p ${BUILD_DIR}
	GOOS=linux GOARCH=amd64 go build ${GOMOD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-linux-amd64
	GOOS=linux GOARCH=arm64 go build ${GOMOD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-linux-arm64
	GOOS=darwin GOARCH=amd64 go build ${GOMOD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-darwin-amd64
	GOOS=darwin GOARCH=arm64 go build ${GOMOD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-darwin-arm64
	GOOS=windows GOARCH=amd64 go build ${GOMOD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-windows-amd64.exe
	@echo "${GREEN}All platform builds complete${NC}"
	@ls -la ${BUILD_DIR}/

install: build ## Install the binary to GOPATH/bin
	@echo "${GREEN}Installing ${BINARY_NAME}...${NC}"
	go install ${GOMOD} ${LDFLAGS}
	@echo "${GREEN}Installation complete${NC}"

# Development targets
deps: ## Download and verify dependencies
	@echo "${GREEN}Downloading dependencies...${NC}"
	go mod download
	go mod verify
	@echo "${GREEN}Dependencies updated${NC}"

format: ## Format Go code
	@echo "${GREEN}Formatting code...${NC}"
	gofmt -s -w .
	@echo "${GREEN}Code formatting complete${NC}"

vet: ## Run go vet
	@echo "${GREEN}Running go vet...${NC}"
	go vet ./...
	@echo "${GREEN}go vet passed${NC}"

lint: ## Run linters (requires golangci-lint)
	@echo "${GREEN}Running linters...${NC}"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "${YELLOW}golangci-lint not found, skipping...${NC}"; \
	fi

check: format vet ## Run all code quality checks
	@echo "${GREEN}All checks passed${NC}"

# Test targets
test: test-unit ## Run all tests
	@echo "${GREEN}All tests completed${NC}"

test-unit: ## Run unit tests
	@echo "${GREEN}Running unit tests...${NC}"
	@mkdir -p ${COVERAGE_DIR}
	go test -v -race -coverprofile=${COVERAGE_DIR}/coverage.out ./...
	@echo "${GREEN}Unit tests completed${NC}"

test-integration: build ## Run integration tests
	@echo "${GREEN}Running integration tests...${NC}"
	@mkdir -p ${TEST_RESULTS_DIR}
	@$(MAKE) test-good
	@$(MAKE) test-bad
	@$(MAKE) test-features
	@echo "${GREEN}Integration tests completed${NC}"

test-good: build ## Test with good signature files (should succeed)
	@echo "${GREEN}Testing good signature files...${NC}"
	@success=0; total=0; \
	for file in testfiles/good/*; do \
		if [ -f "$$file" ]; then \
			echo "Testing $$file..."; \
			total=$$((total + 1)); \
			if timeout 30 ${BUILD_DIR}/${BINARY_NAME} "$$file" > ${TEST_RESULTS_DIR}/$$(basename "$$file").log 2>&1; then \
				echo "${GREEN}✓ SUCCESS: $$file${NC}"; \
				success=$$((success + 1)); \
			else \
				echo "${RED}✗ FAILED: $$file${NC}"; \
				echo "Output:"; \
				cat ${TEST_RESULTS_DIR}/$$(basename "$$file").log; \
			fi; \
		fi; \
	done; \
	echo "Good files: $$success/$$total succeeded"; \
	if [ $$success -ne $$total ]; then \
		echo "${RED}Not all good files passed!${NC}"; \
		exit 1; \
	fi

test-bad: build ## Test with bad signature files (should fail gracefully)
	@echo "${GREEN}Testing bad signature files...${NC}"
	@graceful=0; total=0; \
	for file in testfiles/bad/*; do \
		if [ -f "$$file" ]; then \
			echo "Testing $$file..."; \
			total=$$((total + 1)); \
			if timeout 30 ${BUILD_DIR}/${BINARY_NAME} "$$file" > ${TEST_RESULTS_DIR}/$$(basename "$$file").log 2>&1; then \
				if grep -q "no valid signature found\|Error:" ${TEST_RESULTS_DIR}/$$(basename "$$file").log; then \
					echo "${GREEN}✓ GRACEFUL FAILURE: $$file${NC}"; \
					graceful=$$((graceful + 1)); \
				else \
					echo "${YELLOW}⚠ UNEXPECTED SUCCESS: $$file${NC}"; \
				fi; \
			else \
				exit_code=$$?; \
				if [ $$exit_code -eq 1 ]; then \
					echo "${GREEN}✓ GRACEFUL FAILURE: $$file${NC}"; \
					graceful=$$((graceful + 1)); \
				elif [ $$exit_code -eq 124 ]; then \
					echo "${RED}✗ TIMEOUT: $$file${NC}"; \
					exit 1; \
				else \
					echo "${RED}✗ CRASH: $$file (exit code: $$exit_code)${NC}"; \
					exit 1; \
				fi; \
			fi; \
		fi; \
	done; \
	echo "Bad files: $$graceful/$$total failed gracefully"

test-features: build ## Test specific features
	@echo "${GREEN}Testing features...${NC}"

	# Test algorithm listing
	@echo "Testing algorithm listing..."
	@${BUILD_DIR}/${BINARY_NAME} -list > ${TEST_RESULTS_DIR}/algorithm-list.log
	@if grep -q "Total supported OIDs:" ${TEST_RESULTS_DIR}/algorithm-list.log; then \
		echo "${GREEN}✓ Algorithm listing works${NC}"; \
	else \
		echo "${RED}✗ Algorithm listing failed${NC}"; \
		exit 1; \
	fi

	# Test help output
	@echo "Testing help output..."
	@${BUILD_DIR}/${BINARY_NAME} -help > ${TEST_RESULTS_DIR}/help.log 2>&1 || true
	@if grep -q "Usage:" ${TEST_RESULTS_DIR}/help.log; then \
		echo "${GREEN}✓ Help output works${NC}"; \
	else \
		echo "${RED}✗ Help output failed${NC}"; \
		exit 1; \
	fi

	# Test file saving behavior
	@echo "Testing file saving behavior..."
	@if [ -f "testfiles/good/bootx64.efi" ]; then \
		rm -f signature.der custom.der; \
		${BUILD_DIR}/${BINARY_NAME} testfiles/good/bootx64.efi > /dev/null 2>&1; \
		if [ -f "signature.der" ]; then \
			echo "${RED}✗ File created without -s flag${NC}"; \
			exit 1; \
		else \
			echo "${GREEN}✓ No file created without -s flag${NC}"; \
		fi; \
		${BUILD_DIR}/${BINARY_NAME} -s testfiles/good/bootx64.efi > /dev/null 2>&1; \
		if [ -f "signature.der" ]; then \
			echo "${GREEN}✓ File created with -s flag${NC}"; \
			rm signature.der; \
		else \
			echo "${RED}✗ File not created with -s flag${NC}"; \
			exit 1; \
		fi; \
		${BUILD_DIR}/${BINARY_NAME} -s -o custom.der testfiles/good/bootx64.efi > /dev/null 2>&1; \
		if [ -f "custom.der" ]; then \
			echo "${GREEN}✓ Custom filename works${NC}"; \
			rm custom.der; \
		else \
			echo "${RED}✗ Custom filename failed${NC}"; \
			exit 1; \
		fi; \
	else \
		echo "${YELLOW}⚠ Test file not found, skipping save behavior test${NC}"; \
	fi

coverage: test-unit ## Generate and display coverage report
	@echo "${GREEN}Generating coverage report...${NC}"
	@mkdir -p ${COVERAGE_DIR}
	go tool cover -html=${COVERAGE_DIR}/coverage.out -o ${COVERAGE_DIR}/coverage.html
	go tool cover -func=${COVERAGE_DIR}/coverage.out
	@echo "${GREEN}Coverage report generated: ${COVERAGE_DIR}/coverage.html${NC}"

benchmark: ## Run benchmarks
	@echo "${GREEN}Running benchmarks...${NC}"
	go test -bench=. -benchmem ./...

# CI targets
ci: deps check build test-unit test-integration ## Run full CI pipeline locally
	@echo "${GREEN}🎉 CI pipeline completed successfully${NC}"

ci-fast: deps vet build test-unit ## Run fast CI checks
	@echo "${GREEN}🚀 Fast CI pipeline completed${NC}"

# Utility targets
clean: ## Clean build artifacts and test results
	@echo "${GREEN}Cleaning build artifacts...${NC}"
	rm -rf ${BUILD_DIR}
	rm -rf ${COVERAGE_DIR}
	rm -rf ${TEST_RESULTS_DIR}
	rm -f signature.der custom.der *.der
	go clean -cache -testcache
	@echo "${GREEN}Clean complete${NC}"

version: ## Display version information
	@echo "autograph-pls"
	@echo "Version: ${VERSION}"
	@echo "Build Time: ${BUILD_TIME}"
	@echo "Git Commit: ${GIT_COMMIT}"
	@echo "Go Version: $(shell go version)"

info: version ## Display project information
	@echo ""
	@echo "Project Structure:"
	@echo "- Source files: $(shell find . -name '*.go' | wc -l) Go files"
	@echo "- Test files: $(shell find . -name '*_test.go' | wc -l) test files"
	@echo "- Good test files: $(shell ls testfiles/good/* 2>/dev/null | wc -l) files"
	@echo "- Bad test files: $(shell ls testfiles/bad/* 2>/dev/null | wc -l) files"
	@echo "- Supported OIDs: $(shell grep -c '".*":' parsesign.go || echo "N/A")"

docs: ## Generate documentation
	@echo "${GREEN}Generating documentation...${NC}"
	go doc -all > docs.txt
	@echo "${GREEN}Documentation generated: docs.txt${NC}"

setup-dev: ## Set up development environment
	@echo "${GREEN}Setting up development environment...${NC}"
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@echo "${GREEN}Development environment setup complete${NC}"

# Docker targets (optional)
docker-build: ## Build Docker image
	@echo "${GREEN}Building Docker image...${NC}"
	docker build -t ${BINARY_NAME}:${VERSION} .

docker-test: docker-build ## Test Docker image
	@echo "${GREEN}Testing Docker image...${NC}"
	docker run --rm -v $(PWD)/testfiles:/app/testfiles ${BINARY_NAME}:${VERSION} -list

# Release targets
release: clean build-all test ## Prepare release build
	@echo "${GREEN}Release build completed${NC}"
	@echo "Binaries available in ${BUILD_DIR}/"

# Make sure these directories exist
$(BUILD_DIR) $(COVERAGE_DIR) $(TEST_RESULTS_DIR):
	@mkdir -p $@

# Prevent make from trying to build files named like targets
.SUFFIXES:

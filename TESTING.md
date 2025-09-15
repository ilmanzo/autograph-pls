# Testing Guide for autograph-pls

## 📋 Overview

This document provides comprehensive information about testing the autograph-pls ASN.1 signature parser, including unit tests, integration tests, CI/CD pipeline, and testing best practices.

## 🧪 Test Suite Structure

### Test Categories

1. **Unit Tests** (`*_test.go`): Test individual functions and components
2. **Integration Tests**: Test complete workflows with real files
3. **Robustness Tests**: Test error handling and edge cases
4. **Performance Tests**: Benchmark critical functions
5. **Memory Safety Tests**: Verify bounds checking and resource management

### Test Files Organization

```
autograph-pls/
├── parsesign_test.go              # Main test suite
├── testfiles/
│   ├── good/                      # Valid signature files (should succeed)
│   │   ├── bootx64.efi
│   │   ├── grub-x86_64.efi
│   │   ├── linux-x86_64
│   │   └── ...
│   └── bad/                       # Malformed files (should fail gracefully)
│       ├── bad_file1
│       ├── bad_file2
│       ├── bad_file3
│       └── bad_file4
├── .github/workflows/ci.yml       # GitHub Actions CI
└── Makefile                       # Build and test automation
```

## 🚀 Quick Start

### Running All Tests

```bash
# Run complete test suite
make test

# Run only unit tests
make test-unit

# Run integration tests
make test-integration

# Run with coverage
make coverage
```

### Manual Go Testing

```bash
# Run unit tests with verbose output
go test -v

# Run tests with race detection
go test -race

# Run tests with coverage
go test -coverprofile=coverage.out
go tool cover -html=coverage.out

# Run specific test
go test -run TestParseASN1Element

# Run benchmarks
go test -bench=.
```

## 📊 Test Coverage

### Current Test Coverage Areas

#### ✅ Core ASN.1 Parsing
- **`TestParseASN1Element`**: Tests basic ASN.1 element parsing
- **`TestGetTagName`**: Tests tag name resolution for all classes
- **`TestFormatPrimitiveContent`**: Tests content formatting for different types
- **`TestOIDRecognition`**: Tests OID parsing and name mapping

#### ✅ Signature Validation
- **`TestSignatureValidation`**: Tests field validation logic
- **`TestSignatureValidationComplete`**: Tests complete vs incomplete validation
- **Error handling for malformed certificate fields**

#### ✅ File Handling
- **`TestFileHandling`**: Tests file loading and saving operations
- **Error cases for nonexistent files and invalid paths**
- **Memory mapping functionality**

#### ✅ Robustness & Safety
- **`TestBoundsChecking`**: Tests slice bounds protection
- **`TestRecursionLimits`**: Tests recursion depth limits
- **`TestErrorHandling`**: Tests comprehensive error scenarios
- **`TestMemorySafety`**: Tests with various input sizes
- **`TestConcurrency`**: Tests thread safety

#### ✅ Integration Tests
- **`TestIntegrationWithRealFiles`**: Tests with actual signature files
- **Good files validation (should find valid signatures)**
- **Bad files handling (should fail gracefully without crashes)**

#### ✅ CLI & Configuration
- **`TestDisplayResults`**: Tests output formatting
- **`TestASN1Displayer`**: Tests ASN.1 structure display

### Performance Benchmarks

- **`BenchmarkParseASN1Element`**: ASN.1 parsing performance
- **`BenchmarkOIDParsing`**: OID parsing performance
- **`BenchmarkSignatureValidation`**: Validation performance

## 🏗 CI/CD Pipeline

### GitHub Actions Workflow (`.github/workflows/ci.yml`)

#### Multi-Platform Testing
- **Operating Systems**: Ubuntu, macOS, Windows
- **Go Versions**: 1.19, 1.20, 1.21
- **Architecture**: AMD64, ARM64 (where supported)

#### Pipeline Stages

1. **Code Quality Checks**
   ```yaml
   - go vet ./...
   - gofmt check
   - dependency verification
   ```

2. **Build Verification**
   ```yaml
   - go build for all platforms
   - binary functionality test
   ```

3. **Unit Testing**
   ```yaml
   - go test -v -race -coverprofile=coverage.out
   - coverage report generation
   - test result artifacts
   ```

4. **Integration Testing**
   ```yaml
   - Test good files (should succeed)
   - Test bad files (should fail gracefully)
   - Feature testing (algorithm listing, help, file saving)
   - Performance testing
   - Memory safety verification
   ```

5. **Security Scanning**
   ```yaml
   - gosec security analysis
   - SARIF report upload
   ```

6. **Release Build Testing** (on main branch)
   ```yaml
   - Multi-platform release builds
   - Binary artifact generation
   ```

### Expected Test Results

#### Good Files (`testfiles/good/*`)
- ✅ **Expected**: Program succeeds (exit code 0)
- ✅ **Expected**: Valid signature found and parsed
- ✅ **Expected**: Certificate fields validated
- ✅ **Expected**: ASN.1 structure displayed correctly

#### Bad Files (`testfiles/bad/*`)
- ✅ **Expected**: Program fails gracefully (exit code 1)
- ✅ **Expected**: Error message displayed (no crash)
- ✅ **Expected**: "no valid signature found" or similar error
- ❌ **Failure**: Program crash, timeout, or unexpected success

## 🔧 Adding New Tests

### Unit Test Template

```go
func TestNewFeature(t *testing.T) {
    tests := []struct {
        name        string
        input       interface{}
        expected    interface{}
        expectError bool
    }{
        {
            name:        "Valid case",
            input:       validInput,
            expected:    expectedOutput,
            expectError: false,
        },
        {
            name:        "Error case",
            input:       invalidInput,
            expectError: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := functionUnderTest(tt.input)

            if tt.expectError {
                if err == nil {
                    t.Error("Expected error but got none")
                }
                return
            }

            if err != nil {
                t.Errorf("Unexpected error: %v", err)
                return
            }

            if result != tt.expected {
                t.Errorf("Expected %v, got %v", tt.expected, result)
            }
        })
    }
}
```

### Integration Test Template

```go
func TestIntegrationNewScenario(t *testing.T) {
    // Setup
    testFile := "testfiles/test-scenario.bin"
    if _, err := os.Stat(testFile); os.IsNotExist(err) {
        t.Skip("Test file not found")
    }

    // Test execution with error recovery
    defer func() {
        if r := recover(); r != nil {
            t.Errorf("Test panicked: %v", r)
        }
    }()

    // Run actual test
    fh := FileHandler{}
    data, cleanup, err := fh.LoadFile(testFile)
    if err != nil {
        t.Fatalf("Failed to load test file: %v", err)
    }
    defer cleanup()

    parser := NewSignatureParser(data)
    raw, offset, err := parser.FindValidSignature()

    // Assertions
    // ... test specific validations
}
```

### Benchmark Template

```go
func BenchmarkNewFunction(b *testing.B) {
    // Setup
    testData := setupBenchmarkData()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        result := functionToBenchmark(testData)
        _ = result // Prevent optimization
    }
}
```

## 🐛 Testing Edge Cases

### Critical Edge Cases Covered

1. **Malformed ASN.1 Data**
   - Invalid tag bytes
   - Excessive length values
   - Truncated structures
   - Negative length values

2. **Memory Safety**
   - Large file handling (up to 50MB limit)
   - Deep recursion (MaxRecursionDepth = 50)
   - Excessive element counts (MaxElementsPerLevel = 10000)

3. **Bounds Checking**
   - Slice bounds validation
   - Array access safety
   - Integer overflow protection

4. **Error Recovery**
   - Panic recovery mechanisms
   - Graceful degradation
   - Partial result handling

## 📈 Performance Testing

### Performance Targets

- **File Loading**: < 100ms for typical files
- **ASN.1 Parsing**: < 10ms for standard signatures
- **Memory Usage**: < 100MB for largest test files
- **Recursion Depth**: Limited to 50 levels

### Benchmark Results Format

```
BenchmarkParseASN1Element-8        1000000    1045 ns/op     320 B/op    3 allocs/op
BenchmarkOIDParsing-8              5000000     234 ns/op      64 B/op    2 allocs/op
BenchmarkSignatureValidation-8      100000   12450 ns/op    2048 B/op   15 allocs/op
```

## 🔍 Debugging Tests

### Running Tests with Debug Output

```bash
# Verbose test output
go test -v

# Run specific test with debug
go test -v -run TestSpecificFunction

# Test with race detector
go test -race -v

# Test with CPU profiling
go test -cpuprofile=cpu.prof -bench=.

# Test with memory profiling
go test -memprofile=mem.prof -bench=.
```

### Common Test Failures & Solutions

1. **"slice bounds out of range"**
   - **Cause**: Insufficient bounds checking
   - **Solution**: Add validation before slice operations

2. **"timeout exceeded"**
   - **Cause**: Infinite loops or excessive processing
   - **Solution**: Add recursion limits and timeouts

3. **"race condition detected"**
   - **Cause**: Concurrent access to shared resources
   - **Solution**: Use proper synchronization or avoid shared state

## 📋 Test Maintenance

### Regular Test Maintenance Tasks

1. **Update test files** when adding new signature formats
2. **Add performance tests** for new critical functions
3. **Update CI matrix** when supporting new Go versions
4. **Review test coverage** and add tests for uncovered code
5. **Update documentation** when test structure changes

### Test File Management

- **Good files**: Add new legitimate signature files to `testfiles/good/`
- **Bad files**: Add malformed/corrupted files to `testfiles/bad/`
- **File naming**: Use descriptive names indicating file type/purpose
- **File size**: Keep test files reasonably small (< 10MB each)

## 🎯 Quality Gates

### CI Success Criteria

- ✅ All unit tests pass on all platforms
- ✅ All integration tests pass
- ✅ Code coverage > 80%
- ✅ No security vulnerabilities detected
- ✅ All good files parse successfully
- ✅ All bad files fail gracefully (no crashes)
- ✅ Performance within acceptable limits
- ✅ Memory safety verified

### Manual Testing Checklist

Before major releases:

- [ ] Test on multiple operating systems
- [ ] Verify with large signature files
- [ ] Test with unusual/edge case signatures
- [ ] Validate error messages are user-friendly
- [ ] Check memory usage with large files
- [ ] Verify all command-line options work
- [ ] Test concurrent execution scenarios

## 📚 Additional Resources

- **Go Testing Documentation**: https://golang.org/pkg/testing/
- **GitHub Actions**: https://docs.github.com/en/actions
- **Test Coverage Best Practices**: Go community standards
- **ASN.1 Standards**: ITU-T X.690 for reference data

---

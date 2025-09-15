package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Test data constants
const (
	// Valid ASN.1 SEQUENCE header (0x30 0x82 followed by length)
	validASN1Header = "308201234567890abcdef"

	// Invalid ASN.1 data that should be handled gracefully
	invalidASN1Data = "ffff"

	// Sample OID for commonName (2.5.4.3)
	commonNameOID = "060355040b"

	// Sample UTF8String "Test CA"
	testCAString = "0c07546573742043411"
)

// TestParseASN1Element tests the core ASN.1 parsing functionality
func TestParseASN1Element(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		depth       int
		offset      int
		expectError bool
		expectedTag int
		expectedLen int
	}{
		{
			name:        "Valid SEQUENCE",
			input:       []byte{0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
			depth:       0,
			offset:      0,
			expectError: false,
			expectedTag: 16, // SEQUENCE
			expectedLen: 5,
		},
		{
			name:        "Valid INTEGER",
			input:       []byte{0x02, 0x01, 0xFF},
			depth:       0,
			offset:      0,
			expectError: false,
			expectedTag: 2, // INTEGER
			expectedLen: 1,
		},
		{
			name:        "Insufficient data",
			input:       []byte{0x30},
			depth:       0,
			offset:      0,
			expectError: true,
		},
		{
			name:        "Maximum recursion depth",
			input:       []byte{0x30, 0x02, 0x01, 0x01},
			depth:       MaxRecursionDepth + 1,
			offset:      0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			element, bytesRead, err := parseASN1Element(tt.input, tt.depth, tt.offset)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if element.Tag != tt.expectedTag {
				t.Errorf("Expected tag %d, got %d", tt.expectedTag, element.Tag)
			}

			if element.Length != tt.expectedLen {
				t.Errorf("Expected length %d, got %d", tt.expectedLen, element.Length)
			}

			if bytesRead <= 0 {
				t.Errorf("Expected positive bytesRead, got %d", bytesRead)
			}
		})
	}
}

// TestGetTagName tests ASN.1 tag name resolution
func TestGetTagName(t *testing.T) {
	tests := []struct {
		tag          int
		class        int
		isCompound   bool
		expectedName string
	}{
		{TagBoolean, 0, false, "BOOLEAN"},
		{TagInteger, 0, false, "INTEGER"},
		{TagSequence, 0, true, "SEQUENCE"},
		{TagSet, 0, true, "SET"},
		{TagUTF8String, 0, false, "UTF8String"},
		{TagPrintable, 0, false, "PrintableString"},
		{TagBMPString, 0, false, "BMPString"},
		{TagReal, 0, false, "REAL"},
		{TagEnumerated, 0, false, "ENUMERATED"},
		{0, 1, false, "APPLICATION [0]"},                // Application class
		{0, 2, false, "CONTEXT [0] (version/keyUsage)"}, // Context-specific
		{1, 2, true, "CONTEXT [1] (issuerUniqueID/subjectAltName)"},
		{0, 3, false, "PRIVATE [0]"},     // Private class
		{99, 0, false, "PRIMITIVE [99]"}, // Unknown universal tag
	}

	for _, tt := range tests {
		t.Run(tt.expectedName, func(t *testing.T) {
			result := getTagName(tt.tag, tt.class, tt.isCompound)
			if result != tt.expectedName {
				t.Errorf("Expected '%s', got '%s'", tt.expectedName, result)
			}
		})
	}
}

// TestOIDRecognition tests OID parsing and recognition
func TestOIDRecognition(t *testing.T) {
	tests := []struct {
		name         string
		oidBytes     []byte
		expectedOID  string
		expectedName string
		hasName      bool
	}{
		{
			name:         "Common Name OID",
			oidBytes:     []byte{0x55, 0x04, 0x03}, // 2.5.4.3
			expectedOID:  "2.5.4.3",
			expectedName: "commonName",
			hasName:      true,
		},
		{
			name:         "RSA Encryption OID",
			oidBytes:     []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}, // 1.2.840.113549.1.1.1
			expectedOID:  "1.2.840.113549.1.1.1",
			expectedName: "rsaEncryption",
			hasName:      true,
		},
		{
			name:        "Empty OID",
			oidBytes:    []byte{},
			expectedOID: "",
			hasName:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseOID(tt.oidBytes)
			if result != tt.expectedOID {
				t.Errorf("Expected OID '%s', got '%s'", tt.expectedOID, result)
			}

			if tt.hasName {
				if name, exists := oidNames[tt.expectedOID]; !exists {
					t.Errorf("Expected OID '%s' to have a name", tt.expectedOID)
				} else if name != tt.expectedName {
					t.Errorf("Expected name '%s', got '%s'", tt.expectedName, name)
				}
			}
		})
	}
}

// TestSignatureValidation tests signature field validation
func TestSignatureValidation(t *testing.T) {
	tests := []struct {
		name     string
		oid      string
		value    string
		expected SignatureValidation
	}{
		{
			name:  "Common Name",
			oid:   OIDCommonName,
			value: "Test CA",
			expected: SignatureValidation{
				HasCommonName: true,
				CommonName:    "Test CA",
			},
		},
		{
			name:  "Country Name",
			oid:   OIDCountryName,
			value: "US",
			expected: SignatureValidation{
				HasCountryName: true,
				CountryName:    "US",
			},
		},
		{
			name:  "Email Address",
			oid:   OIDEmailAddress,
			value: "test@example.com",
			expected: SignatureValidation{
				HasEmailAddress: true,
				EmailAddress:    "test@example.com",
			},
		},
	}

	parser := &SignatureParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validation := &SignatureValidation{}
			parser.setValidationField(validation, tt.oid, tt.value)

			if !reflect.DeepEqual(*validation, tt.expected) {
				t.Errorf("Expected validation %+v, got %+v", tt.expected, *validation)
			}
		})
	}
}

// TestSignatureValidationComplete tests complete validation
func TestSignatureValidationComplete(t *testing.T) {
	completeValidation := SignatureValidation{
		HasCommonName:       true,
		HasCountryName:      true,
		HasLocalityName:     true,
		HasOrganizationName: true,
		HasEmailAddress:     true,
		CommonName:          "Test CA",
		CountryName:         "US",
		LocalityName:        "Test City",
		OrganizationName:    "Test Org",
		EmailAddress:        "test@example.com",
	}

	incompleteValidation := SignatureValidation{
		HasCommonName: true,
		CommonName:    "Test CA",
		// Missing other required fields
	}

	if !completeValidation.IsValid() {
		t.Error("Complete validation should be valid")
	}

	if incompleteValidation.IsValid() {
		t.Error("Incomplete validation should not be valid")
	}
}

// TestFormatPrimitiveContent tests content formatting for different ASN.1 types
func TestFormatPrimitiveContent(t *testing.T) {
	tests := []struct {
		name     string
		tag      int
		content  []byte
		expected string
	}{
		{
			name:     "Boolean True",
			tag:      TagBoolean,
			content:  []byte{0xFF},
			expected: "TRUE",
		},
		{
			name:     "Boolean False",
			tag:      TagBoolean,
			content:  []byte{0x00},
			expected: "FALSE",
		},
		{
			name:     "Small Integer",
			tag:      TagInteger,
			content:  []byte{0x01, 0x23},
			expected: "291 (0x0123)",
		},
		{
			name:     "UTF8 String",
			tag:      TagUTF8String,
			content:  []byte("Test String"),
			expected: "\"Test String\"",
		},
		{
			name:     "Null",
			tag:      TagNull,
			content:  []byte{},
			expected: "",
		},
		{
			name:     "Enumerated",
			tag:      TagEnumerated,
			content:  []byte{0x02},
			expected: "ENUM(2)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatPrimitiveContent(tt.tag, tt.content)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestFileHandling tests file loading and saving operations
func TestFileHandling(t *testing.T) {
	// Create a temporary test file
	testData := []byte("test signature data")
	tmpFile, err := os.CreateTemp("", "test-signature-*.der")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(testData); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}
	tmpFile.Close()

	fh := FileHandler{}

	// Test file loading
	t.Run("LoadFile", func(t *testing.T) {
		data, cleanup, err := fh.LoadFile(tmpFile.Name())
		if err != nil {
			t.Fatalf("Failed to load file: %v", err)
		}
		defer cleanup()

		if !bytes.Equal(data, testData) {
			t.Errorf("Expected data %v, got %v", testData, data)
		}
	})

	// Test file saving
	t.Run("SaveToFile", func(t *testing.T) {
		outputFile := tmpFile.Name() + ".out"
		defer os.Remove(outputFile)

		err := fh.SaveToFile(testData, outputFile)
		if err != nil {
			t.Fatalf("Failed to save file: %v", err)
		}

		savedData, err := os.ReadFile(outputFile)
		if err != nil {
			t.Fatalf("Failed to read saved file: %v", err)
		}

		if !bytes.Equal(savedData, testData) {
			t.Errorf("Expected saved data %v, got %v", testData, savedData)
		}
	})

	// Test error cases
	t.Run("LoadNonexistentFile", func(t *testing.T) {
		_, _, err := fh.LoadFile("nonexistent-file.der")
		if err == nil {
			t.Error("Expected error for nonexistent file")
		}
	})

	t.Run("SaveToInvalidPath", func(t *testing.T) {
		err := fh.SaveToFile(testData, "/invalid/path/file.der")
		if err == nil {
			t.Error("Expected error for invalid save path")
		}
	})
}

// TestBoundsChecking tests that bounds checking prevents crashes
func TestBoundsChecking(t *testing.T) {
	// Test with malformed ASN.1 data that could cause slice bounds errors
	malformedData := [][]byte{
		{0x30, 0xFF},                   // Invalid length
		{0x30, 0x82, 0xFF, 0xFF, 0xFF}, // Extremely large length
		{},                             // Empty data
		{0x30},                         // Incomplete header
	}

	parser := NewSignatureParser([]byte{})

	for i, data := range malformedData {
		t.Run(fmt.Sprintf("MalformedData_%d", i), func(t *testing.T) {
			// This should not panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Panic occurred with malformed data: %v", r)
				}
			}()

			parser.data = data
			validation := &SignatureValidation{}
			parser.findFieldsInASN1WithDepth(data, validation, 0)
		})
	}
}

// TestRecursionLimits tests that recursion limits prevent infinite loops
func TestRecursionLimits(t *testing.T) {
	// Create deeply nested ASN.1 structure that would exceed limits
	parser := NewSignatureParser([]byte{})
	validation := &SignatureValidation{}

	// This should not cause infinite recursion
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Panic occurred during recursion limit test: %v", r)
		}
	}()

	// Test with maximum depth + 1
	parser.findFieldsInASN1WithDepth([]byte{0x30, 0x02, 0x01, 0x01}, validation, MaxRecursionDepth+1)
}

// TestDisplayResults tests the display functionality
func TestDisplayResults(t *testing.T) {
	results := DisplayResults{
		Validation: SignatureValidation{
			HasCommonName:   true,
			CommonName:      "Test CA",
			HasCountryName:  true,
			CountryName:     "US",
			HasLocalityName: false,
		},
		KeySize: 2048,
		Offset:  1024,
		Size:    512,
	}

	// Capture output
	var buf bytes.Buffer
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	done := make(chan bool)
	go func() {
		buf.ReadFrom(r)
		done <- true
	}()

	results.Print()

	w.Close()
	os.Stdout = oldStdout
	<-done

	output := buf.String()

	// Check that output contains expected information
	expectedStrings := []string{
		"Signature Validation:",
		"Common Name: true (Test CA)",
		"Country Name: true (US)",
		"Locality Name: false",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("Output missing expected string: %s", expected)
		}
	}
}

// TestASN1Displayer tests the ASN.1 structure display
func TestASN1Displayer(t *testing.T) {
	// Simple ASN.1 SEQUENCE with INTEGER
	testData := []byte{0x30, 0x03, 0x02, 0x01, 0x42} // SEQUENCE { INTEGER 66 }

	displayer := ASN1Displayer{}

	// Capture output
	var buf bytes.Buffer
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	done := make(chan bool)
	go func() {
		buf.ReadFrom(r)
		done <- true
	}()

	err := displayer.Display(testData, 0)

	w.Close()
	os.Stdout = oldStdout
	<-done

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "SEQUENCE") {
		t.Error("Output missing SEQUENCE")
	}
	if !strings.Contains(output, "INTEGER") {
		t.Error("Output missing INTEGER")
	}
}

// TestIntegrationWithRealFiles tests the tool with actual test files
func TestIntegrationWithRealFiles(t *testing.T) {
	// Check if testfiles directory exists
	if _, err := os.Stat("testfiles"); os.IsNotExist(err) {
		t.Skip("testfiles directory not found, skipping integration tests")
	}

	// Test good files
	t.Run("GoodFiles", func(t *testing.T) {
		goodFiles, err := filepath.Glob("testfiles/good/*")
		if err != nil {
			t.Fatalf("Failed to list good files: %v", err)
		}

		if len(goodFiles) == 0 {
			t.Skip("No good test files found")
		}

		for _, file := range goodFiles {
			t.Run(filepath.Base(file), func(t *testing.T) {
				fh := FileHandler{}
				data, cleanup, err := fh.LoadFile(file)
				if err != nil {
					t.Fatalf("Failed to load file %s: %v", file, err)
				}
				defer cleanup()

				parser := NewSignatureParser(data)
				raw, offset, err := parser.FindValidSignature()

				if err != nil {
					t.Errorf("Failed to find signature in %s: %v", file, err)
					return
				}

				if raw == nil {
					t.Errorf("No signature found in %s", file)
					return
				}

				if offset < 0 {
					t.Errorf("Invalid offset %d for %s", offset, file)
				}

				// Test validation
				validation := parser.validateSignatureFields(raw.FullBytes)
				if !validation.IsValid() {
					t.Logf("Warning: %s has incomplete signature validation", file)
				}
			})
		}
	})

	// Test bad files
	t.Run("BadFiles", func(t *testing.T) {
		badFiles, err := filepath.Glob("testfiles/bad/*")
		if err != nil {
			t.Fatalf("Failed to list bad files: %v", err)
		}

		for _, file := range badFiles {
			t.Run(filepath.Base(file), func(t *testing.T) {
				fh := FileHandler{}
				data, cleanup, err := fh.LoadFile(file)
				if err != nil {
					t.Fatalf("Failed to load file %s: %v", file, err)
				}
				defer cleanup()

				// This should not panic
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("Panic occurred with bad file %s: %v", file, r)
					}
				}()

				parser := NewSignatureParser(data)
				_, _, err = parser.FindValidSignature()

				// Bad files should either return an error or find no valid signature
				// The important thing is that it doesn't crash
				if err == nil {
					t.Logf("Bad file %s unexpectedly found a signature", file)
				}
			})
		}
	})
}

// BenchmarkParseASN1Element benchmarks ASN.1 parsing performance
func BenchmarkParseASN1Element(b *testing.B) {
	testData := []byte{0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := parseASN1Element(testData, 0, 0)
		if err != nil {
			b.Fatalf("Parse error: %v", err)
		}
	}
}

// BenchmarkOIDParsing benchmarks OID parsing performance
func BenchmarkOIDParsing(b *testing.B) {
	// RSA encryption OID: 1.2.840.113549.1.1.1
	oidBytes := []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := parseOID(oidBytes)
		if result != "1.2.840.113549.1.1.1" {
			b.Fatalf("Incorrect OID result: %s", result)
		}
	}
}

// BenchmarkSignatureValidation benchmarks signature field validation
func BenchmarkSignatureValidation(b *testing.B) {
	// Create test ASN.1 data with some certificate fields
	testData := make([]byte, 1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	parser := NewSignatureParser(testData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validation := parser.validateSignatureFields(testData)
		_ = validation.IsValid()
	}
}

// TestErrorHandling tests comprehensive error handling
func TestErrorHandling(t *testing.T) {
	tests := []struct {
		name string
		test func() error
	}{
		{
			name: "EmptyData",
			test: func() error {
				parser := NewSignatureParser([]byte{})
				_, _, err := parser.FindValidSignature()
				return err
			},
		},
		{
			name: "TooSmallData",
			test: func() error {
				parser := NewSignatureParser([]byte{0x30})
				_, _, err := parser.FindValidSignature()
				return err
			},
		},
		{
			name: "InvalidASN1Structure",
			test: func() error {
				invalidData := []byte{0x30, 0x82, 0xFF, 0xFF} // Invalid large length
				parser := NewSignatureParser(invalidData)
				_, _, err := parser.FindValidSignature()
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.test()
			if err == nil {
				t.Errorf("Expected error for test %s but got none", tt.name)
			}
		})
	}
}

// TestMemorySafety tests memory safety with various input sizes
func TestMemorySafety(t *testing.T) {
	sizes := []int{0, 1, 10, 100, 1000, 10000}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i % 256)
			}

			// This should not crash or consume excessive memory
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Panic with size %d: %v", size, r)
				}
			}()

			parser := NewSignatureParser(data)
			validation := &SignatureValidation{}
			parser.findFieldsInASN1WithDepth(data, validation, 0)
		})
	}
}

// TestConcurrency tests that the parser is safe for concurrent use
func TestConcurrency(t *testing.T) {
	testData := []byte{0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}
	numGoroutines := 10

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Panic in goroutine: %v", r)
				}
				done <- true
			}()

			parser := NewSignatureParser(testData)
			validation := &SignatureValidation{}
			parser.findFieldsInASN1WithDepth(testData, validation, 0)
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent tests")
		}
	}
}

// TestHelperFunctions tests utility helper functions
func TestHelperFunctions(t *testing.T) {
	// Test that all required OIDs are present
	requiredOIDs := []string{
		OIDCommonName,
		OIDCountryName,
		OIDLocalityName,
		OIDOrganizationName,
		OIDEmailAddress,
	}

	for _, oid := range requiredOIDs {
		if _, exists := oidNames[oid]; !exists {
			t.Errorf("Required OID %s not found in oidNames map", oid)
		}
	}

	// Test that we have a reasonable number of OIDs
	if len(oidNames) < 100 {
		t.Errorf("Expected at least 100 OIDs, got %d", len(oidNames))
	}
}

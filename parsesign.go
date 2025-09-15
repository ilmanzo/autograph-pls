package main

import (
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// ASN.1 tag constants
const (
	TagSequence    = 16
	TagSet         = 17
	TagInteger     = 2
	TagOctetString = 4
	TagObjectID    = 6
	TagBitString   = 3
	TagNull        = 5
	TagUTF8String  = 12
	TagPrintable   = 19
	TagT61String   = 20
	TagIA5String   = 22
	TagUTCTime     = 23
	TagGeneralTime = 24
)

// Common certificate field OIDs
const (
	OIDCommonName       = "2.5.4.3"
	OIDCountryName      = "2.5.4.6"
	OIDLocalityName     = "2.5.4.7"
	OIDOrganizationName = "2.5.4.10"
	OIDEmailAddress     = "1.2.840.113549.1.9.1"
)

// Common OID mappings for display
var oidNames = map[string]string{
	"1.2.840.113549.1.1.1":   "rsaEncryption",
	"1.2.840.113549.1.1.5":   "sha1WithRSAEncryption",
	"1.2.840.113549.1.1.11":  "sha256WithRSAEncryption",
	"1.2.840.113549.1.1.12":  "sha384WithRSAEncryption",
	"1.2.840.113549.1.1.13":  "sha512WithRSAEncryption",
	"1.2.840.10045.2.1":      "ecPublicKey",
	"1.2.840.10045.4.3.2":    "ecdsa-with-SHA256",
	"2.16.840.1.101.3.4.2.1": "sha256",
	"2.16.840.1.101.3.4.2.2": "sha384",
	"2.16.840.1.101.3.4.2.3": "sha512",
	"1.3.14.3.2.26":          "sha1",
	OIDCommonName:            "commonName",
	OIDCountryName:           "countryName",
	OIDLocalityName:          "localityName",
	OIDOrganizationName:      "organizationName",
	OIDEmailAddress:          "emailAddress",
}

// Config holds command-line configuration
type Config struct {
	FilePath   string
	SaveFile   bool
	OutputFile string
}

// SignatureValidation holds validation results for signature fields
type SignatureValidation struct {
	HasCommonName       bool
	HasCountryName      bool
	HasLocalityName     bool
	HasOrganizationName bool
	HasEmailAddress     bool
	CommonName          string
	CountryName         string
	LocalityName        string
	OrganizationName    string
	EmailAddress        string
}

// IsValid returns true if all required certificate fields are present
func (sv SignatureValidation) IsValid() bool {
	return sv.HasCommonName && sv.HasCountryName && sv.HasLocalityName &&
		sv.HasOrganizationName && sv.HasEmailAddress
}

// ASN1Element represents a parsed ASN.1 element for display
type ASN1Element struct {
	Depth      int
	Offset     int
	HeaderLen  int
	Length     int
	Tag        int
	Class      int
	IsCompound bool
	TagName    string
	Content    string
}

// SignatureParser handles parsing and validation of ASN.1 signatures
type SignatureParser struct {
	data []byte
}

// NewSignatureParser creates a new signature parser
func NewSignatureParser(data []byte) *SignatureParser {
	return &SignatureParser{data: data}
}

// FindValidSignature searches backwards for valid signature with 0x30 0x82 marker
func (sp *SignatureParser) FindValidSignature() (*asn1.RawValue, int, error) {
	// Search backwards for 0x30 0x82 pattern
	for i := len(sp.data) - 2; i >= 0; i-- {
		if sp.data[i] == 0x30 && sp.data[i+1] == 0x82 {
			// Try to parse ASN.1 structure from this position
			buffer := sp.data[i:]
			var raw asn1.RawValue
			_, err := asn1.Unmarshal(buffer, &raw)
			if err != nil {
				continue // Invalid structure, continue searching
			}

			// Validate signature fields
			validation := sp.validateSignatureFields(raw.FullBytes)
			if !validation.IsValid() {
				continue // Missing required fields, continue searching
			}

			return &raw, i, nil
		}
	}

	return nil, 0, errors.New("no valid signature found")
}

// validateSignatureFields checks for required certificate fields in ASN.1 data
func (sp *SignatureParser) validateSignatureFields(data []byte) SignatureValidation {
	validation := SignatureValidation{}
	sp.findFieldsInASN1(data, &validation)
	return validation
}

// findFieldsInASN1 recursively searches for certificate fields
func (sp *SignatureParser) findFieldsInASN1(data []byte, validation *SignatureValidation) {
	offset := 0

	for offset < len(data) {
		element, bytesRead, err := parseASN1Element(data[offset:], 0, offset)
		if err != nil {
			break
		}

		// Check if this is an OID we're looking for
		if element.Tag == TagObjectID && element.Length > 0 {
			content := data[offset+element.HeaderLen : offset+element.HeaderLen+element.Length]
			oid := parseOID(content)

			// Look for the value immediately following this OID
			valueOffset := offset + bytesRead
			if valueOffset < len(data) {
				valueElement, _, err := parseASN1Element(data[valueOffset:], 0, valueOffset)
				if err == nil && !valueElement.IsCompound && valueElement.Length > 0 {
					valueBytes := data[valueOffset+valueElement.HeaderLen : valueOffset+valueElement.HeaderLen+valueElement.Length]
					valueContent := string(valueBytes)

					sp.setValidationField(validation, oid, valueContent)
				}
			}
		}

		// Recursively search in compound elements
		if element.IsCompound && element.Length > 0 {
			contentStart := element.HeaderLen
			if contentStart < bytesRead && element.Length <= len(data[offset:])-contentStart {
				content := data[offset+contentStart : offset+contentStart+element.Length]
				sp.findFieldsInASN1(content, validation)
			}
		}

		offset += bytesRead
	}
}

// setValidationField sets the appropriate validation field based on OID
func (sp *SignatureParser) setValidationField(validation *SignatureValidation, oid, value string) {
	switch oid {
	case OIDCommonName:
		validation.HasCommonName = true
		validation.CommonName = value
	case OIDCountryName:
		validation.HasCountryName = true
		validation.CountryName = value
	case OIDLocalityName:
		validation.HasLocalityName = true
		validation.LocalityName = value
	case OIDOrganizationName:
		validation.HasOrganizationName = true
		validation.OrganizationName = value
	case OIDEmailAddress:
		validation.HasEmailAddress = true
		validation.EmailAddress = value
	}
}

// calculateKeySize calculates key size from the final OCTET STRING
func (sp *SignatureParser) calculateKeySize(data []byte) int {
	keySize := 0
	sp.findLastOctetString(data, &keySize, 0)
	return keySize
}

// findLastOctetString recursively finds the last OCTET STRING element
func (sp *SignatureParser) findLastOctetString(data []byte, keySize *int, depth int) {
	offset := 0
	var lastElement ASN1Element

	for offset < len(data) {
		element, bytesRead, err := parseASN1Element(data[offset:], depth, offset)
		if err != nil {
			break
		}

		lastElement = element

		if element.IsCompound && element.Length > 0 {
			contentStart := element.HeaderLen
			if contentStart < bytesRead && element.Length <= len(data[offset:])-contentStart {
				content := data[offset+contentStart : offset+contentStart+element.Length]
				sp.findLastOctetString(content, keySize, depth+1)
			}
		}

		offset += bytesRead
	}

	// Check if the last element is an OCTET STRING and calculate key size
	if lastElement.Tag == TagOctetString {
		*keySize = lastElement.Length * 8
	}
}

// DisplayResults shows the signature analysis results
type DisplayResults struct {
	Validation SignatureValidation
	KeySize    int
	Offset     int
	Size       int
}

// Print displays the validation results
func (dr DisplayResults) Print() {
	fmt.Println("========================================")
	fmt.Println("Signature Validation:")
	dr.printField("Common Name", dr.Validation.HasCommonName, dr.Validation.CommonName)
	dr.printField("Country Name", dr.Validation.HasCountryName, dr.Validation.CountryName)
	dr.printField("Locality Name", dr.Validation.HasLocalityName, dr.Validation.LocalityName)
	dr.printField("Organization Name", dr.Validation.HasOrganizationName, dr.Validation.OrganizationName)
	dr.printField("Email Address", dr.Validation.HasEmailAddress, dr.Validation.EmailAddress)

	if dr.Validation.IsValid() {
		fmt.Println("✓ Valid signature - all required fields present")
	} else {
		fmt.Println("✗ Invalid signature - missing required fields")
	}
}

// printField prints a validation field with its value
func (dr DisplayResults) printField(name string, hasField bool, value string) {
	fmt.Printf("  %s: %v", name, hasField)
	if hasField && value != "" {
		fmt.Printf(" (%s)", value)
	}
	fmt.Println()
}

// ASN1Displayer handles ASN.1 structure display
type ASN1Displayer struct{}

// Display parses and displays ASN.1 structure
func (ad ASN1Displayer) Display(data []byte, baseOffset int) error {
	return ad.parseAndDisplayASN1(data, 0, baseOffset)
}

// parseAndDisplayASN1 recursively parses and displays ASN.1 structure
func (ad ASN1Displayer) parseAndDisplayASN1(data []byte, depth int, baseOffset int) error {
	offset := 0

	for offset < len(data) {
		element, bytesRead, err := parseASN1Element(data[offset:], depth, baseOffset+offset)
		if err != nil {
			return err
		}

		ad.displayElement(element)

		if element.IsCompound && element.Length > 0 {
			contentStart := element.HeaderLen
			if contentStart < bytesRead && element.Length <= len(data[offset:])-contentStart {
				content := data[offset+contentStart : offset+contentStart+element.Length]
				if err := ad.parseAndDisplayASN1(content, depth+1, baseOffset+offset+contentStart); err != nil {
					// If parsing nested content fails, show as hex dump
					fmt.Printf("%s[HEX DUMP]: %s\n", strings.Repeat("  ", depth+1),
						hex.EncodeToString(content))
				}
			}
		}

		offset += bytesRead
	}

	return nil
}

// displayElement displays a single ASN.1 element
func (ad ASN1Displayer) displayElement(element ASN1Element) {
	lengthStr := fmt.Sprintf("l=%d", element.Length)
	headerStr := fmt.Sprintf("hl=%d", element.HeaderLen)
	depthStr := fmt.Sprintf("d=%d", element.Depth)
	offsetStr := fmt.Sprintf("%d:", element.Offset)

	constructedStr := "prim"
	if element.IsCompound {
		constructedStr = "cons"
	}

	line := fmt.Sprintf("%8s%s %s %s %s: %s",
		offsetStr, depthStr, headerStr, lengthStr, constructedStr, element.TagName)

	if element.Content != "" {
		line += fmt.Sprintf("  %s", element.Content)
	}

	fmt.Println(line)
}

// FileHandler handles file operations
type FileHandler struct{}

// LoadFile loads and memory-maps a file
func (fh FileHandler) LoadFile(filePath string) ([]byte, func() error, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening file: %w", err)
	}

	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("error getting file stats: %w", err)
	}

	fileSize := stat.Size()
	if fileSize < 4 {
		file.Close()
		return nil, nil, errors.New("file too small to contain ASN.1 structure")
	}

	data, err := syscall.Mmap(int(file.Fd()), 0, int(fileSize), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("error memory-mapping file: %w", err)
	}

	cleanup := func() error {
		if err := syscall.Munmap(data); err != nil {
			file.Close()
			return err
		}
		return file.Close()
	}

	return data, cleanup, nil
}

// SaveToFile saves data to a file
func (fh FileHandler) SaveToFile(data []byte, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	return nil
}

// parseConfig parses command line arguments
func parseConfig() (*Config, error) {
	config := &Config{}

	flag.BoolVar(&config.SaveFile, "s", false, "save ASN.1 structure to file (default: signature.der)")
	flag.StringVar(&config.OutputFile, "o", "", "output file to save the ASN.1 structure")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <file_path>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Search for ASN.1 structures (0x30 0x82) from end of file backwards\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		return nil, errors.New("please provide exactly one file path")
	}

	config.FilePath = args[0]
	return config, nil
}

func main() {
	config, err := parseConfig()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}

	fileHandler := FileHandler{}
	data, cleanup, err := fileHandler.LoadFile(config.FilePath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := cleanup(); err != nil {
			fmt.Printf("Warning: failed to cleanup file resources: %v\n", err)
		}
	}()

	fmt.Printf("Analyzing file: %s\n", config.FilePath)
	fmt.Println("========================================")

	parser := NewSignatureParser(data)
	raw, offset, err := parser.FindValidSignature()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Valid ASN.1 signature found at offset %d\n", offset)
	fmt.Printf("Structure size: %d bytes\n", len(raw.FullBytes))

	// Display validation results
	validation := parser.validateSignatureFields(raw.FullBytes)
	keySize := parser.calculateKeySize(raw.FullBytes)

	results := DisplayResults{
		Validation: validation,
		KeySize:    keySize,
		Offset:     offset,
		Size:       len(raw.FullBytes),
	}
	results.Print()

	fmt.Println("========================================")

	// Display ASN.1 structure
	displayer := ASN1Displayer{}
	if err := displayer.Display(raw.FullBytes, offset); err != nil {
		fmt.Printf("Error parsing ASN.1 structure: %v\n", err)
		fmt.Printf("Raw data (hex): %s\n", hex.EncodeToString(raw.FullBytes))
	}

	fmt.Printf("Key size calculation: ")
	if keySize > 0 {
		fmt.Printf("%d bits\n", keySize)
	} else {
		fmt.Printf("N/A (no OCTET STRING found as final element)\n")
	}

	fmt.Println("========================================")

	// Save to file if requested
	if config.SaveFile || config.OutputFile != "" {
		filename := config.OutputFile
		if filename == "" {
			filename = "signature.der"
		}

		if err := fileHandler.SaveToFile(raw.FullBytes, filename); err != nil {
			fmt.Printf("Error saving to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("ASN.1 structure saved to: %s\n", filename)
	}
}

// parseASN1Element parses a single ASN.1 element
func parseASN1Element(data []byte, depth int, offset int) (ASN1Element, int, error) {
	if len(data) < 2 {
		return ASN1Element{}, 0, errors.New("insufficient data for ASN.1 element")
	}

	element := ASN1Element{
		Depth:  depth,
		Offset: offset,
	}

	// Parse tag
	tagByte := data[0]
	element.Class = int((tagByte & 0xC0) >> 6)
	element.IsCompound = (tagByte & 0x20) != 0
	element.Tag = int(tagByte & 0x1F)

	bytesRead := 1

	// Parse length
	lengthByte := data[1]
	bytesRead++

	if lengthByte&0x80 == 0 {
		// Short form
		element.Length = int(lengthByte)
		element.HeaderLen = bytesRead
	} else {
		// Long form
		lengthOctets := int(lengthByte & 0x7F)
		if lengthOctets == 0 {
			return element, 0, errors.New("indefinite length not supported")
		}
		if len(data) < bytesRead+lengthOctets {
			return element, 0, errors.New("insufficient data for length octets")
		}

		element.Length = 0
		for i := 0; i < lengthOctets; i++ {
			element.Length = (element.Length << 8) | int(data[bytesRead])
			bytesRead++
		}
		element.HeaderLen = bytesRead
	}

	// Set tag name and content
	element.TagName = getTagName(element.Tag, element.IsCompound)

	if !element.IsCompound && element.Length > 0 && len(data) >= element.HeaderLen+element.Length {
		content := data[element.HeaderLen : element.HeaderLen+element.Length]
		element.Content = formatPrimitiveContent(element.Tag, content)
	}

	totalBytes := element.HeaderLen + element.Length
	if totalBytes > len(data) {
		return element, 0, errors.New("element extends beyond available data")
	}

	return element, totalBytes, nil
}

// getTagName returns a human-readable name for the ASN.1 tag
func getTagName(tag int, isCompound bool) string {
	if isCompound {
		switch tag {
		case TagSequence:
			return "SEQUENCE"
		case TagSet:
			return "SET"
		default:
			return fmt.Sprintf("CONSTRUCTED [%d]", tag)
		}
	} else {
		switch tag {
		case 1:
			return "BOOLEAN"
		case TagInteger:
			return "INTEGER"
		case TagBitString:
			return "BIT STRING"
		case TagOctetString:
			return "OCTET STRING"
		case TagNull:
			return "NULL"
		case TagObjectID:
			return "OBJECT IDENTIFIER"
		case TagUTF8String:
			return "UTF8String"
		case TagPrintable:
			return "PrintableString"
		case TagT61String:
			return "T61String"
		case TagIA5String:
			return "IA5String"
		case TagUTCTime:
			return "UTCTime"
		case TagGeneralTime:
			return "GeneralizedTime"
		default:
			return fmt.Sprintf("PRIMITIVE [%d]", tag)
		}
	}
}

// formatPrimitiveContent formats the content of primitive ASN.1 elements
func formatPrimitiveContent(tag int, content []byte) string {
	switch tag {
	case 1: // BOOLEAN
		if len(content) == 1 {
			if content[0] == 0 {
				return "FALSE"
			}
			return "TRUE"
		}
		return hex.EncodeToString(content)

	case TagInteger: // INTEGER
		if len(content) <= 8 {
			// Small integers - show as decimal and hex
			var value int64
			for _, b := range content {
				value = (value << 8) | int64(b)
			}
			if len(content) > 0 && content[0]&0x80 != 0 {
				// Handle negative numbers
				for i := len(content); i < 8; i++ {
					value |= int64(0xFF) << (8 * (7 - i))
				}
			}
			return fmt.Sprintf("%d (0x%X)", value, content)
		}
		// Large integers - show as hex
		return hex.EncodeToString(content)

	case TagBitString: // BIT STRING
		if len(content) > 0 {
			unusedBits := content[0]
			data := content[1:]
			if len(data) > 32 {
				return fmt.Sprintf("unused bits: %d, data: %s... (%d bytes)", unusedBits, hex.EncodeToString(data[:32]), len(data))
			}
			return fmt.Sprintf("unused bits: %d, data: %s", unusedBits, hex.EncodeToString(data))
		}
		return hex.EncodeToString(content)

	case TagOctetString: // OCTET STRING
		if len(content) > 32 {
			return fmt.Sprintf("%s... (%d bytes)", hex.EncodeToString(content[:32]), len(content))
		}
		return hex.EncodeToString(content)

	case TagNull: // NULL
		return ""

	case TagObjectID: // OBJECT IDENTIFIER
		oid := parseOID(content)
		if name, exists := oidNames[oid]; exists {
			return fmt.Sprintf("%s (%s)", oid, name)
		}
		return oid

	case TagUTF8String, TagPrintable, TagT61String, TagIA5String: // String types
		return fmt.Sprintf("%q", string(content))

	case TagUTCTime, TagGeneralTime: // Time types
		return fmt.Sprintf("%q", string(content))

	default:
		if len(content) > 32 {
			return fmt.Sprintf("%s... (%d bytes)", hex.EncodeToString(content[:32]), len(content))
		}
		return hex.EncodeToString(content)
	}
}

// parseOID parses an ASN.1 OBJECT IDENTIFIER
func parseOID(content []byte) string {
	if len(content) == 0 {
		return ""
	}

	var oid []string

	// First subidentifier encodes first two arc values
	if len(content) > 0 {
		first := content[0]
		oid = append(oid, fmt.Sprintf("%d", first/40))
		oid = append(oid, fmt.Sprintf("%d", first%40))
	}

	// Remaining subidentifiers
	i := 1
	for i < len(content) {
		var value uint64
		for i < len(content) {
			b := content[i]
			i++
			value = (value << 7) | uint64(b&0x7F)
			if b&0x80 == 0 {
				break
			}
		}
		oid = append(oid, fmt.Sprintf("%d", value))
	}

	return strings.Join(oid, ".")
}

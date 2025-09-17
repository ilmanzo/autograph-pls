# autograph-pls - Enhanced ASN.1 Signature Parser and Validator

A comprehensive tool for parsing, validating, and analyzing ASN.1 digital signatures in binary files. This enhanced version supports over 150 cryptographic algorithms and provides detailed signature analysis for various file formats including EFI, PE, and other signed binaries.

## 🚀 Features

### Core Functionality
- **Backward signature search**: Efficiently searches for ASN.1 structures (0x30 0x82 pattern) from file end backwards
- **Certificate field validation**: Validates presence of required certificate fields (CN, C, L, O, emailAddress)
- **Key size calculation**: Automatically determines cryptographic key sizes
- **ASN.1 structure display**: Comprehensive hierarchical display of ASN.1 elements
- **Signature extraction**: Save discovered signatures to external files

### Enhanced Algorithm Recognition
- **151+ supported OIDs**: Comprehensive mapping of cryptographic object identifiers
- **Modern algorithms**: Support for post-quantum, EdDSA, and latest NIST standards
- **International standards**: GOST (Russian), SM series (Chinese), Camellia (Japanese)
- **Legacy support**: Backward compatibility with older signature formats
- **FIDO/WebAuthn**: Support for modern authentication standards

## 📋 Supported Cryptographic Algorithms

### Signature Algorithms
- **RSA**: RSA-PSS, SHA-1/224/256/384/512 with RSA, MD2/MD5 with RSA
- **ECDSA**: P-256, P-384, P-521, secp256k1, Brainpool curves
- **DSA**: Classic DSA with SHA-1/224/256
- **EdDSA**: Ed25519, Ed448
- **Post-Quantum**: ML-DSA (Dilithium), Falcon, ML-KEM (Kyber)
- **GOST**: Russian GOST R 34.10-2001/2012 (256/512-bit)
- **SM**: Chinese SM2 signature algorithm

### Hash Functions
- **SHA Family**: SHA-1, SHA-2 (224/256/384/512), SHA-3, SHAKE
- **Legacy**: MD5, MD2
- **International**: GOST R 34.11, SM3

### Encryption Algorithms
- **Symmetric**: AES (128/192/256), ChaCha20-Poly1305, Camellia
- **Legacy**: 3DES, RC2, RC4
- **International**: GOST 28147-89, GOST R 34.12-2015, SM4

## 🛠 Installation

### Prerequisites
- Go 1.19 or later
- Git

### Build from Source
```bash
git clone <repository-url>
cd autograph-pls
go mod init autograph-pls
go build -o autograph-pls
```

## 📖 Usage

### Basic Analysis
```bash
# Analyze a signed EFI file
./autograph-pls myfile.efi

# Analyze with signature extraction
./autograph-pls -s -o extracted_signature.der myfile.exe

# List all supported algorithms
./autograph-pls -list
```

### Command Line Options
- `-s`: Write signature to external file
- `-o <filename>`: Specify output file name (default: signature.der)
- `-list`: Display all supported cryptographic algorithms and OIDs
- `-help`: Show detailed usage information

## 📊 Output Format

### Signature Validation Results
```
========================================
Signature Validation:
  Common Name: true (Example CA)
  Country Name: true (US)
  Locality Name: true (San Francisco)
  Organization Name: true (Example Corp)
  Email Address: true (ca@example.com)
✓ Valid signature - all required fields present
========================================
```

### ASN.1 Structure Display
```
offset:d=depth hl=header_len l=content_len prim/cons: TAG_NAME  content
Example:
965082:d=5 hl=2 l=3 prim: OBJECT IDENTIFIER  2.5.4.3 (commonName)
965087:d=5 hl=2 l=36 prim: UTF8String  "SUSE Linux Enterprise Secure Boot CA"
```

### Field Explanations
- **offset**: Byte offset in file where element starts
- **d=depth**: Nesting depth in ASN.1 structure
- **hl=header_len**: Length of ASN.1 header in bytes
- **l=content_len**: Length of content in bytes
- **prim/cons**: Primitive or constructed element
- **TAG_NAME**: Human-readable ASN.1 tag name
- **content**: Decoded content (for primitive elements)

## 🔍 Technical Details

### ASN.1 Structure Recognition
The tool identifies ASN.1 signatures by:
1. Searching backward from file end for 0x30 0x82 pattern
2. Attempting to parse valid ASN.1 structure from each candidate position
3. Validating presence of required certificate distinguished name fields
4. Confirming structural integrity of the signature

### Key Size Calculation
- Automatically detects key sizes by analyzing the final OCTET STRING element
- Supports RSA, ECDSA, and DSA key size detection
- Reports key size in bits (e.g., 2048 bits for RSA-2048)

### Certificate Field Validation
Required fields for valid signature:
- **Common Name (CN)**: Certificate authority or signer name
- **Country Name (C)**: Two-letter country code
- **Locality Name (L)**: City or locality
- **Organization Name (O)**: Organization name
- **Email Address**: Contact email address

## 🌍 International Algorithm Support

### Russian GOST Standards
- GOST R 34.10-2001/2012 (signature algorithms)
- GOST R 34.11-94/2012 (hash functions)
- GOST 28147-89, Magma, Kuznyechik (encryption)

### Chinese SM Standards
- SM2 (elliptic curve signature)
- SM3 (hash function)
- SM4 (block cipher)

### Japanese Standards
- Camellia encryption algorithm family

## 🔮 Post-Quantum Cryptography
Support for NIST-standardized post-quantum algorithms:
- **ML-DSA**: Module-Lattice-Based Digital Signature (Dilithium)
- **ML-KEM**: Module-Lattice-Based Key Encapsulation (Kyber)
- **Falcon**: Fast-Fourier Lattice-based Compact Signatures

## 🤝 Contributing

Contributions are welcome! Areas for enhancement:
- Additional algorithm support
- New file format recognition
- Performance optimizations
- Extended validation rules
- Additional international standards

## 📜 License

[Include your license information here]

## 🔧 Troubleshooting

### Common Issues
1. **No signature found**: Ensure the file actually contains embedded signatures
2. **Insufficient data error**: File may be truncated or corrupted
3. **Invalid structure**: File may use non-standard signature format

### Debug Tips
- Use `-list` to verify algorithm support
- Check file size (minimum 4 bytes required)
- Verify file hasn't been modified after signing

## 📈 Performance

- **Memory-mapped I/O**: Efficient handling of large files
- **Backward search**: Optimized for typical signature placement at file end
- **Minimal memory usage**: Processes files without loading entire content into RAM

---

**Version**: Enhanced ASN.1 Parser v2.0  
**Supported OIDs**: 151+  
**Last Updated**: 2024
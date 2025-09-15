# ASN.1 Tag Reference Guide

## Overview

This document provides a comprehensive reference for ASN.1 (Abstract Syntax Notation One) tags supported by the enhanced autograph-pls parser. ASN.1 uses a tag-length-value (TLV) encoding scheme where each data element is identified by a tag that indicates its type and structure.

## Tag Structure

ASN.1 tags consist of:
- **Tag Class** (2 bits): Universal, Application, Context-specific, or Private
- **Constructed Flag** (1 bit): Primitive (0) or Constructed (1)
- **Tag Number** (5+ bits): Specific tag identifier

### Tag Classes

| Class | Value | Description | Usage |
|-------|-------|-------------|-------|
| Universal | 0 | Standard ASN.1 types | Built-in types like INTEGER, BOOLEAN, etc. |
| Application | 1 | Application-specific | Defined by specific applications |
| Context-specific | 2 | Context-dependent | Local to a particular structure |
| Private | 3 | Private use | Organization-specific definitions |

## Universal Tags (Class 0)

### Basic Data Types

| Tag | Name | Type | Description | Example Content |
|-----|------|------|-------------|-----------------|
| 1 | BOOLEAN | Primitive | Boolean value | `TRUE` or `FALSE` |
| 2 | INTEGER | Primitive | Integer value | `42`, `0x1A2B3C4D` |
| 3 | BIT STRING | Primitive | String of bits | `unused bits: 3, data: A1B2C3...` |
| 4 | OCTET STRING | Primitive | String of bytes | `48656C6C6F20576F726C64` |
| 5 | NULL | Primitive | Null value | (empty) |
| 6 | OBJECT IDENTIFIER | Primitive | Unique object ID | `1.2.840.113549.1.1.1 (rsaEncryption)` |
| 7 | ObjectDescriptor | Primitive | Object description | `"RSA Public Key Algorithm"` |
| 8 | EXTERNAL | Constructed | External reference | Complex external data reference |
| 9 | REAL | Primitive | Real number | IEEE 754 floating point |
| 10 | ENUMERATED | Primitive | Enumerated value | `ENUM(3)` |
| 11 | EMBEDDED PDV | Constructed | Embedded data | Presentation data value |
| 12 | UTF8String | Primitive | UTF-8 text | `"Hello World"` |
| 13 | RELATIVE-OID | Primitive | Relative OID | `1.2.3` (relative to base OID) |

### Structured Types

| Tag | Name | Type | Description |
|-----|------|------|-------------|
| 16 | SEQUENCE | Constructed | Ordered collection |
| 17 | SET | Constructed | Unordered collection |

### String Types

| Tag | Name | Type | Character Set | Description |
|-----|------|------|---------------|-------------|
| 18 | NumericString | Primitive | 0-9, space | `"12345 678"` |
| 19 | PrintableString | Primitive | A-Z, a-z, 0-9, limited punctuation | `"Hello World"` |
| 20 | T61String | Primitive | T.61 character set | Teletex string |
| 21 | VideotexString | Primitive | Videotex character set | Legacy videotex |
| 22 | IA5String | Primitive | ASCII (7-bit) | `"user@example.com"` |
| 25 | GraphicString | Primitive | ISO 2022 graphic chars | Graphics string |
| 26 | VisibleString | Primitive | ISO 646 visible chars | `"VisibleText"` |
| 27 | GeneralString | Primitive | General character string | Generic string |
| 28 | UniversalString | Primitive | ISO 10646 (4-byte) | Unicode string |
| 29 | CHARACTER STRING | Constructed | Abstract character string | Complex character data |
| 30 | BMPString | Primitive | Basic multilingual plane | Unicode BMP (2-byte) |

### Time Types

| Tag | Name | Type | Format | Description |
|-----|------|------|--------|-------------|
| 23 | UTCTime | Primitive | YYMMDDHHMMSSZ | `"231225140000Z"` |
| 24 | GeneralizedTime | Primitive | YYYYMMDDHHMMSS[.f]Z | `"20231225140000Z"` |

## Context-Specific Tags (Class 2)

These tags are context-dependent and their meaning varies based on the structure they appear in. Common usage in X.509 certificates:

### X.509 Certificate Structure

| Tag | Context | Meaning | Usage |
|-----|---------|---------|-------|
| [0] | TBSCertificate | Version | Certificate version (v1, v2, v3) |
| [0] | GeneralName | otherName | Alternative name form |
| [0] | Extensions | authorityKeyIdentifier | Authority key identifier |
| [1] | TBSCertificate | issuerUniqueID | Unique identifier for issuer |
| [1] | GeneralName | rfc822Name | Email address |
| [1] | Extensions | subjectKeyIdentifier | Subject key identifier |
| [2] | TBSCertificate | subjectUniqueID | Unique identifier for subject |
| [2] | GeneralName | dNSName | DNS name |
| [2] | Extensions | keyUsage | Key usage constraints |
| [3] | TBSCertificate | extensions | Certificate extensions |
| [3] | GeneralName | x400Address | X.400 address |
| [4] | GeneralName | directoryName | X.500 directory name |
| [5] | GeneralName | ediPartyName | EDI party name |
| [6] | GeneralName | uniformResourceIdentifier | URI |
| [7] | GeneralName | iPAddress | IP address |
| [8] | GeneralName | registeredID | Registered OID |

### Common Extension Context Tags

| Tag | Extension | Description |
|-----|-----------|-------------|
| [0] | BasicConstraints | cA boolean |
| [1] | BasicConstraints | pathLenConstraint |
| [0] | AuthorityKeyIdentifier | keyIdentifier |
| [1] | AuthorityKeyIdentifier | authorityCertIssuer |
| [2] | AuthorityKeyIdentifier | authorityCertSerialNumber |

### CMS/PKCS#7 Context Tags

| Tag | Context | Meaning |
|-----|---------|---------|
| [0] | SignedData | version |
| [1] | SignedData | digestAlgorithms |
| [2] | SignedData | contentInfo |
| [3] | SignedData | certificates |
| [4] | SignedData | crls |
| [5] | SignedData | signerInfos |

## Application-Specific Tags (Class 1)

Application-specific tags are defined by individual applications or standards:

### Common Application Tags

| Tag | Standard | Usage |
|-----|----------|-------|
| [0] | LDAP | Search filters |
| [1] | LDAP | Attribute descriptions |
| [2] | LDAP | Attribute values |
| [0] | Kerberos | Ticket |
| [1] | Kerberos | Authenticator |
| [2] | Kerberos | EncTicketPart |

## Private Tags (Class 3)

Private tags are defined by organizations for their own use and are not standardized.

## Tag Encoding Examples

### Simple Tags (Tag < 31)
```
Tag = 02 (INTEGER)
├─ Class: 00 (Universal)
├─ Constructed: 0 (Primitive) 
└─ Tag Number: 00010 (2)
```

### Long Form Tags (Tag ≥ 31)
```
First Byte: 1F (Tag 31 in long form)
├─ Class: 00 (Universal)
├─ Constructed: 0 (Primitive)
└─ Tag Number: 11111 (31 = long form indicator)

Subsequent bytes encode the actual tag number
```

### Context-Specific Example
```
Tag = A0 (Context-specific [0])
├─ Class: 10 (Context-specific)
├─ Constructed: 1 (Constructed)
└─ Tag Number: 00000 (0)
```

## Practical Examples in Signatures

### X.509 Certificate Structure
```
SEQUENCE {                           // Tag 30 (SEQUENCE)
  tbsCertificate SEQUENCE {          // Tag 30 (SEQUENCE)
    version [0] INTEGER OPTIONAL,    // Tag A0 (CONTEXT [0])
    serialNumber INTEGER,            // Tag 02 (INTEGER)
    signature SEQUENCE,              // Tag 30 (SEQUENCE)
    issuer Name,                     // Tag 30 (SEQUENCE)
    validity SEQUENCE,               // Tag 30 (SEQUENCE)
    subject Name,                    // Tag 30 (SEQUENCE)
    subjectPublicKeyInfo SEQUENCE,   // Tag 30 (SEQUENCE)
    extensions [3] Extensions OPT    // Tag A3 (CONTEXT [3])
  },
  signatureAlgorithm SEQUENCE,       // Tag 30 (SEQUENCE)
  signatureValue BIT STRING          // Tag 03 (BIT STRING)
}
```

### PKCS#7 SignedData Structure
```
SEQUENCE {                           // Tag 30 (SEQUENCE)
  contentType OBJECT IDENTIFIER,     // Tag 06 (OBJECT IDENTIFIER)
  content [0] EXPLICIT SEQUENCE {    // Tag A0 (CONTEXT [0])
    version INTEGER,                 // Tag 02 (INTEGER)
    digestAlgorithms SET,            // Tag 31 (SET)
    contentInfo SEQUENCE,            // Tag 30 (SEQUENCE)
    certificates [0] IMPLICIT SET,   // Tag A0 (CONTEXT [0])
    signerInfos SET                  // Tag 31 (SET)
  }
}
```

## Enhanced autograph-pls Recognition

The enhanced parser now recognizes:

✅ **All 30+ Universal Tags**: Complete ASN.1 universal tag set  
✅ **Context-Specific Tags**: With X.509/CMS semantic hints  
✅ **Application Tags**: Basic application-specific recognition  
✅ **Private Tags**: Private tag identification  
✅ **Tag Classes**: Proper class identification and display  
✅ **Long Form Tags**: Support for extended tag numbers  
✅ **Semantic Hints**: Context-aware tag naming for certificates  

### Example Output
```
965082:d=5 hl=2 l=3 prim: OBJECT IDENTIFIER  2.5.4.3 (commonName)
965270:d=1 hl=2 l=123 cons: CONTEXT [0] (version/keyUsage)
965410:d=1 hl=4 l=256 prim: OCTET STRING  397f1b5c... (256 bytes)
```

## References

- **ITU-T X.690**: ASN.1 encoding rules (BER, CER, DER)
- **RFC 5280**: Internet X.509 Public Key Infrastructure Certificate
- **RFC 5652**: Cryptographic Message Syntax (CMS)
- **ITU-T X.680**: ASN.1 specification
- **ITU-T X.208**: Legacy ASN.1 specification

## Notes

1. **Tag Numbers 14-15**: Reserved for future use in universal class
2. **Context-Specific**: Meaning depends entirely on context
3. **Constructed vs Primitive**: Constructed tags contain other tags
4. **DER Encoding**: Distinguished Encoding Rules used in certificates
5. **Tag Extensions**: Tags ≥ 31 use long form encoding

This reference covers all ASN.1 tags that may appear in digital signatures, certificates, and related cryptographic structures.
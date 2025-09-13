package main

import (
    "encoding/asn1"
    "fmt"
    "os"
    "syscall"
)

func main() {
    if len(os.Args) != 2 {
        fmt.Println("Usage: go run parsesign.go <file_path>")
        os.Exit(1)
    }
    filePath := os.Args[1]

    file, err := os.Open(filePath)
    if err != nil {
        fmt.Printf("Error opening file: %v\n", err)
        os.Exit(1)
    }
    defer file.Close()

    stat, err := file.Stat()
    if err != nil {
        fmt.Printf("Error getting file stats: %v\n", err)
        os.Exit(1)
    }

    fileSize := stat.Size()
    if fileSize == 0 {
        fmt.Println("Error: File is empty.")
        return
    }

    // Memory-map the file for read-only access. This is more efficient
    // for large files than reading the entire content into a byte slice.
    // Note: syscall.Mmap is OS-specific (works on Linux/macOS/BSD).
    data, err := syscall.Mmap(int(file.Fd()), 0, int(fileSize), syscall.PROT_READ, syscall.MAP_SHARED)
    if err != nil {
        fmt.Printf("Error memory-mapping file: %v\n", err)
        os.Exit(1)
    }
    defer syscall.Munmap(data)

    // Iterate backwards from the end of the file data.
    for i := len(data) - 1; i >= 0; i-- {
        // A DER SEQUENCE starts with the byte 0x30.
        if data[i] != 0x30 {
            continue
        }

        // Get the slice of data from the potential start to the end.
        buffer := data[i:]

        // Use asn1.Unmarshal to see if it's a valid structure.
        // We use a RawValue to capture any valid ASN.1 structure.
        var raw asn1.RawValue
        remainingBytes, err := asn1.Unmarshal(buffer, &raw)

        // If there's no error and no remaining bytes, we found it.
        if err == nil && len(remainingBytes) == 0 {
            fmt.Printf("Found a potential ASN.1 structure starting at byte offset: %d\n", i)
            fmt.Println("----------------------------------------")
            // The standard library doesn't have a built-in pretty-printer
            // like asn1parse, but we can show the basic structure.
            fmt.Printf("Tag: %d (Class: %d)\n", raw.Tag, raw.Class)
            fmt.Printf("IsConstructed: %v\n", raw.IsCompound)
            fmt.Printf("Length: %d bytes\n", len(raw.Bytes))
            fmt.Printf("Full ASN.1 block (Hex): %X\n", raw.FullBytes)
            fmt.Println("----------------------------------------")
            return
        }
    }

    fmt.Println("No valid ASN.1 signature found at the end of the file.")
}
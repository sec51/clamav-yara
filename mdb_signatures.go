package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// With MDB (and MSB) format the PE Section Hash is always md5
// By default we assume the hash function is md5
type mdbSignature struct {
	PeSectionSize uint64
	IsSha1        bool
	IsSha256      bool
}

// parse the whole file
func parseMDBSignatures(headerName string, data string) []*platformSigs {
	var platforms []*platformSigs
	// ANY platform container for the respective signatures
	anyPlatform := newPlatformSigs(kANY_PLATFORM)

	// split the file via new line
	fileRows := parseFile(headerName, data)

	// loop thorugh each row string and parse it
	for _, row := range fileRows {
		sig := new(signature)
		// parse the ndb signature format
		mdbSignature := parseMdbSignatureRow(row, sig)
		if mdbSignature != nil {
			sig.MdbSig = mdbSignature
			anyPlatform.AddSigs(sig)
		}
	}

	anyPlatform.TotalSignatures = len(anyPlatform.Sigs)
	anyPlatform.LastGeneration = time.Now().UTC()
	platforms = append(platforms, anyPlatform)
	return platforms
}

// Parse a single definition's row
func parseMdbSignatureRow(row string, signature *signature) *mdbSignature {
	tokens := strings.Split(row, ":")
	if len(tokens) == 0 || len(row) == 0 {
		//fmt.Printf("Could not parse NDB signature. Empty row: %s\n", row)
		return nil
	}

	sig := new(mdbSignature)
	signature.IsMdbSignature = true

	var err error
	var sectionSize uint64
	for index, value := range tokens {
		switch index {
		case 0: // PeSectionSize
			// this means any size. This slows down the matching , therefore for now we skip it
			if value == "*" {
				return nil
			}
			sectionSize, err = strconv.ParseUint(value, 10, 64)
			if err != nil {
				fmt.Printf("MDB Signature failed to parse PE section size %s\n", err)
				return nil
			}
			sig.PeSectionSize = sectionSize
			continue
		case 1: // PeSectionHash
			signature.SigHash = value
			if len(value) == 40 {
				sig.IsSha1 = true
			}

			if len(value) == 64 {
				sig.IsSha256 = true
			}
		case 2:
			signature.MalwareName = sanitizeMalwareName(value)
		}
	}

	return sig
}

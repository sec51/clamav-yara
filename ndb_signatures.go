// WARNING: THIS IS NOT THREAD SAFE !
// AT THE MOMENT THERE IS NO REASON FOR RUNNING THIS CODE IN MULTIPLE ROUTINES
package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type ndbSignature struct {
	//MalwareName        string
	TargetType signatureTarget
	OffsetType uint8
	Offset     uint64
	MaxShift   uint64
	//SigHash            string
	RequirePEModule    bool
	RequireELFModule   bool
	RequireMachOModule bool // YARA does not have it yet, but it is used to identify Mach-O file/process types
	// In order to render the template we need some helper methods to dected what kind of offset we are dealing with
	IsAbsoluteOffset        bool
	IsEndOfFileMinusOffset  bool
	IsEntryPointPlusOffset  bool
	IsEntryPointMinusOffset bool
	IsEntireSectionOffset   bool
	IsStartSectionAtOffset  bool
	IsLastSectionAtOffset   bool
}

// Parse the NDB signatures
// This method has side effects only and creates the spefici yara files with the ndb signatures in it, devided by platform (win, os x, linux)
// If BOTH Offset and MaxShift are zero then it means: any (*)
func parseNDBSignatures(headerName string, data string) []*platformSigs {

	var platforms []*platformSigs

	// OSX container for the respective signatures
	osx := newPlatformSigs(kOSX_PLATFORM)

	// LINUX container for the respective signatures
	linux := newPlatformSigs(kLINUX_PLATFORM)

	// // WIN container for the respective signatures
	win := newPlatformSigs(kWIN_PLATFORM)

	// split the file via new line
	fileRows := parseFile(headerName, data)

	// loop thorugh each row string and parse it
	for _, row := range fileRows {
		sig := new(signature)
		// parse the ndb signature format
		ndbSignature := parseNdbSignatureRow(row, sig)
		if ndbSignature != nil {

			// set the flag for rendering in the template
			sig.IsNdbSignature = true
			// assign the ndb signature to the general one
			sig.NdbSig = ndbSignature

			switch ndbSignature.TargetType {
			// add to all 3 targets
			case kANY_TARGET:

				// YARA does not have a module for MACH-O files yet - so do not flip any flag at the moment
				osx.AddSigs(sig)

				// Linux (ELF)
				nixSig := cloneSignature(sig)
				nixSig.NdbSig.RequireELFModule = true
				linux.AddSigs(nixSig)

				// Win (PE)
				winSig := cloneSignature(sig)
				winSig.NdbSig.RequirePEModule = true
				win.AddSigs(winSig)
				break
				// add to all WIN targets and needs the PE module !
			case kPE_TARGET:
				// set PE module as required
				sig.NdbSig.RequirePEModule = true
				win.AddSigs(sig)
				break
			case kELF_TARGET:
				// set ELF module as required
				sig.NdbSig.RequireELFModule = true
				linux.AddSigs(sig)
				break
			case kMACH_O_TARGET:
				sig.NdbSig.RequireMachOModule = true
				osx.AddSigs(sig)
				break
			}
		}

	}

	osx.TotalSignatures = len(osx.Sigs)
	linux.TotalSignatures = len(linux.Sigs)
	win.TotalSignatures = len(win.Sigs)

	osx.LastGeneration = time.Now().UTC()
	linux.LastGeneration = time.Now().UTC()
	win.LastGeneration = time.Now().UTC()

	// add the platform to the array
	platforms = append(platforms, osx, linux, win)

	return platforms
}

// parse a single NDB signature row
func parseNdbSignatureRow(row string, signature *signature) *ndbSignature {

	tokens := strings.Split(row, ":")
	if len(tokens) == 0 || len(row) == 0 {
		//fmt.Printf("Could not parse NDB signature. Empty row: %s\n", row)
		return nil
	}

	sig := new(ndbSignature)
	sig.RequirePEModule = false // set it to false to start with
	var err error
	var intVal int
	var matched bool
	for index, value := range tokens {

		switch index {
		case 0: // Malware name
			signature.MalwareName = sanitizeMalwareName(value)
			continue
		case 1: // Target type
			// convert the string to an int (TODO: convert it directly to uint8)
			intVal, err = strconv.Atoi(value)
			if err != nil {
				fmt.Printf("NDB Signature TargetType row parsing error: %s\n", err)
				continue
			}
			sig.TargetType = signatureTarget(intVal)
			switch sig.TargetType {
			case kPE_TARGET:
				// set the PE module as required
				sig.RequirePEModule = true
				break
			case kELF_TARGET:
				// set the ELF module as required
				sig.RequireELFModule = true
				break
			default:
				// RESET THE MODULES
				sig.RequirePEModule = false
				sig.RequireELFModule = false
				break
			}
			continue
		case 2: // offset
			// Means ANY
			if value == "*" {
				sig.Offset = 0
				sig.MaxShift = 0
				sig.OffsetType = kANY_OFFSET
				continue
			}

			// #### n
			matched = absoluteOffsetRegex.MatchString(value)
			if matched {
				setOffsetAndShift(kABSOLUTE_OFFSET, absoluteOffsetFormat, value, sig)
				sig.IsAbsoluteOffset = true
				continue
			}

			// #### EOF-n
			matched = endOfFileRegex.MatchString(value)
			if matched {
				setOffsetAndShift(kEND_OF_FILE_MINUS, endOfFileFormat, value, sig)
				sig.IsEndOfFileMinusOffset = true
				continue
			}

			// #### EP+n
			matched = entryPointPlusRegex.MatchString(value)
			if matched {
				setOffsetAndShift(kENTRY_POINT_PLUS, entryPointPlusFormat, value, sig)
				sig.IsEntryPointPlusOffset = true
				continue
			}

			// #### EP-n
			matched = entryPointMinusRegex.MatchString(value)
			if matched {
				setOffsetAndShift(kENTRY_POINT_MINUS, entryPointMinusFormat, value, sig)
				sig.IsEntryPointMinusOffset = true
				continue
			}

			// #### SEx
			matched = entireSectionRegex.MatchString(value)
			if matched {
				setOffsetAndShift(kENTIRE_SECTION_X, entireSectionFormat, value, sig)
				sig.IsEntireSectionOffset = true
				continue
			}

			// #### Sx+n
			matched = startSectionRegex.MatchString(value)
			if matched {
				setOffsetAndShift(kSTART_SECTION_X, startSectionFormat, value, sig)
				sig.IsStartSectionAtOffset = true
				continue
			}

			// #### SL+n
			matched = lastSectionRegex.MatchString(value)
			if matched {
				setOffsetAndShift(kSTART_LAST_SECTION, lastSectionFormat, value, sig)
				sig.IsLastSectionAtOffset = true
				continue
			}

			continue
		case 3: // hex signature
			// this methos converts the format from CLAMAV signature to YARA
			signature.IsString = !regexpHexString.MatchString(value)
			signature.SigHash = translateSignatureToYARA(value)
			continue
		case 4: // optional Min FL
			// this is used only to specify the engine MIN value for ClamAV
			continue
		case 5: // optional Max FL
			// this is used only to specify the engine MAX value for ClamAV
			continue
		}

	}

	return sig
}

// this method is used to set the offset and the max shift on the signature
// created to avoid code duplication
func setOffsetAndShift(offsetType uint8, format, data string, sig *ndbSignature) {
	sig.OffsetType = offsetType
	offset, maxShift := parseOffsetMaxShift(offsetType, format, data)
	sig.Offset = offset
	sig.MaxShift = maxShift
}

// this method parses the single token for the offset and based on the format returns the
// offset and the max shift
func parseOffsetMaxShift(offsetType uint8, format, data string) (uint64, uint64) {

	var offset, maxShift uint64
	var err error

	switch offsetType {
	case kABSOLUTE_OFFSET:
		_, err = fmt.Sscanf(data, absoluteOffsetFormat, &offset)
		break
	case kEND_OF_FILE_MINUS:
		_, err = fmt.Sscanf(data, endOfFileFormat, &offset)
		break
	case kENTRY_POINT_PLUS:
		_, err = fmt.Sscanf(data, entryPointPlusFormat, &maxShift)
		break
	case kENTRY_POINT_MINUS:
		_, err = fmt.Sscanf(data, entryPointMinusFormat, &maxShift)
		break
	case kSTART_SECTION_X:
		_, err = fmt.Sscanf(data, startSectionFormat, &offset, &maxShift)
		break
	case kENTIRE_SECTION_X:
		_, err = fmt.Sscanf(data, entireSectionFormat, &offset)
		break
	case kSTART_LAST_SECTION:
		_, err = fmt.Sscanf(data, lastSectionFormat, &maxShift) // offset is zero
		break
	default:
		fmt.Println("Parsing Offset error:", "Falling to the catch all...")
	}

	if err != nil {
		fmt.Printf("Parsing Offset error %s on format %s for value %s with offset type %d\n", err, format, data, offsetType)
	}

	return offset, maxShift

}

package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	MAIN_NDB_DB  = "main.ndb"
	DAILY_NDB_DB = "daily.ndb"
)

var (

	// EP+n = entry point plus n bytes (EP+0 for EP)
	entryPointPlusRegex  string = "EP+[0-9]+"
	entryPointPlusFormat string = "EP+%d"

	//EP-n = entry point minus n bytes
	entryPointMinusRegex  string = "EP-[0-9]+"
	entryPointMinusFormat string = "EP-%d"

	// Sx+n = start of section x’s (counted from 0) data plus n bytes
	startSectionRegex  string = "S[0-9]+\\+[0-9]+"
	startSectionFormat string = "S%d+%d"

	// SEx = entire section x (offset must lie within section boundaries)
	entireSectionRegex  string = "SE[0-9]+"
	entireSectionFormat string = "SE%d"

	// SL+n = start of last section plus n bytes
	lastSectionRegex  string = "SL[0-9]+"
	lastSectionFormat string = "SL+%d"

	// n
	absoluteOffsetRegex  string = "^[0-9]+"
	absoluteOffsetFormat string = "%d"

	// EOF-n
	endOfFileRegex  string = "EOF-[0-9]+"
	endOfFileFormat string = "EOF-%d"
)

// this struct holds the NDB signature for each platform
type platformNdbSigs struct {
	Platform platform
	Sigs     []*ndbSignature
}

type ndbSignature struct {
	MalwareName        string
	TargetType         signatureTarget
	OffsetType         uint8
	Offset             uint64
	MaxShift           uint64
	SigHash            string
	RequirePEModule    bool
	RequireELFModule   bool
	RequireMachOModule bool // YARA does not have it yet, but it is used to identify Mach-O file/process types
	IsString           bool
	// In order to render the template we need some helper methods to dected what kind of offset we are dealing with
	IsAbsoluteOffset        bool
	IsEndOfFileMinusOffset  bool
	IsEntryPointPlusOffset  bool
	IsEntryPointMinusOffset bool
	IsEntireSectionOffset   bool
	IsStartSectionAtOffset  bool
	IsLastSectionAtOffset   bool
}

func newPlatformNdbSigs(pt platform) *platformNdbSigs {
	sig := new(platformNdbSigs)
	sig.Platform = pt
	return sig
}

// convinient method to add signature to the array
func (pndb *platformNdbSigs) AddSigs(signature *ndbSignature) {
	pndb.Sigs = append(pndb.Sigs, signature)
}

// Used to clone signatires so they can be added to different platform with slightly different flags set
func cloneSignature(originalSig *ndbSignature) *ndbSignature {
	newSignature := *originalSig
	return &newSignature
}

// Parse the NDB signatures
// This method has side effects only and creates the spefici yara files with the ndb signatures in it, devided by platform (win, os x, linux)
// If BOTH Offset and MaxShift are zero then it means: any (*)
func ParseNDBSignatures(headerName string, data string) []*platformNdbSigs {

	var platforms []*platformNdbSigs

	// OSX container for the respective signatures
	osx := newPlatformNdbSigs(OSX_PLATFORM)

	// LINUX container for the respective signatures
	linux := newPlatformNdbSigs(LINUX_PLATFORM)

	// // WIN container for the respective signatures
	win := newPlatformNdbSigs(WIN_PLATFORM)

	// split the file via new line
	fileRows := parseFile(headerName, data)

	// loop thorugh each row string and parse it
	for _, row := range fileRows {

		signature := parseNdbSignatureRow(row)
		if signature != nil {
			switch signature.TargetType {
			// add to all 3 targets
			case ANY_TARGET:

				// YARA does not have a module for MACH-O files yet - so do not flip any flag at the moment
				osx.AddSigs(signature)

				// Linux (ELF)
				nixSig := cloneSignature(signature)
				nixSig.RequireELFModule = true
				linux.AddSigs(nixSig)

				// Win (PE)
				winSig := cloneSignature(signature)
				winSig.RequirePEModule = true
				win.AddSigs(winSig)
				break
				// add to all WIN targets and needs the PE module !
			case PE_TARGET:
				// set PE module as required
				win.AddSigs(signature)
				break
			case ELF_TARGET:
				// set ELF module as required
				linux.AddSigs(signature)
				break
			case MACH_O_TARGET:
				signature.RequireMachOModule = true
				osx.AddSigs(signature)
				break
			}
		}

	}

	// add the platform to the array
	platforms = append(platforms, osx, linux, win)

	return platforms
}

// parse a single NDB signature row
func parseNdbSignatureRow(row string) *ndbSignature {

	tokens := strings.Split(row, ":")
	if len(tokens) == 0 || len(row) == 0 {
		fmt.Printf("Could not parse NDB signature. Empty row: %s\n", row)
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
			sig.MalwareName = sanitizeMalwareName(value)
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
			case PE_TARGET:
				// set the PE module as required
				sig.RequirePEModule = true
				break
			case ELF_TARGET:
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
				sig.OffsetType = ANY_OFFSET
				continue
			}

			// #### n
			matched, err = regexp.MatchString(absoluteOffsetRegex, value)
			if err != nil {
				fmt.Printf("Failed to match n (absolute offset) on the NDB signature offset: %s\n", err)
			}
			if matched {
				setOffsetAndShift(ABSOLUTE_OFFSET, absoluteOffsetFormat, value, sig)
				sig.IsAbsoluteOffset = true
				continue
			}

			// #### EOF-n
			matched, err = regexp.MatchString(endOfFileRegex, value)
			if err != nil {
				fmt.Printf("Failed to match EOF-n on the NDB signature offset: %s\n", err)
			}
			if matched {
				setOffsetAndShift(END_OF_FILE_MINUS, endOfFileFormat, value, sig)
				sig.IsEndOfFileMinusOffset = true
				continue
			}

			// #### EP+n
			matched, err = regexp.MatchString(entryPointPlusRegex, value)
			if err != nil {
				fmt.Printf("Failed to match EP+n on the NDB signature offset: %s\n", err)
			}
			if matched {
				setOffsetAndShift(ENTRY_POINT_PLUS, entryPointPlusFormat, value, sig)
				sig.IsEntryPointPlusOffset = true
				continue
			}

			// #### EP-n
			matched, err = regexp.MatchString(entryPointMinusRegex, value)
			if err != nil {
				fmt.Printf("Failed to match EP-n on the NDB signature offset: %s\n", err)
			}
			if matched {
				setOffsetAndShift(ENTRY_POINT_MINUS, entryPointMinusFormat, value, sig)
				sig.IsEntryPointMinusOffset = true
				continue
			}

			// #### SEx
			matched, err = regexp.MatchString(entireSectionRegex, value)
			if err != nil {
				fmt.Printf("Failed to match SEx on the NDB signature offset: %s\n", err)
			}
			if matched {
				setOffsetAndShift(ENTIRE_SECTION_X, entireSectionFormat, value, sig)
				sig.IsEntireSectionOffset = true
				continue
			}

			// #### Sx+n
			matched, err = regexp.MatchString(startSectionRegex, value)
			if err != nil {
				fmt.Printf("Failed to match Sx+n on the NDB signature offset: %s\n", err)
			}
			if matched {
				setOffsetAndShift(START_SECTION_X, startSectionFormat, value, sig)
				sig.IsStartSectionAtOffset = true
				continue
			}

			// #### SL+n
			matched, err = regexp.MatchString(lastSectionRegex, value)
			if err != nil {
				fmt.Printf("Failed to match SL+n on the NDB signature offset: %s\n", err)
			}
			if matched {
				setOffsetAndShift(START_LAST_SECTION, lastSectionFormat, value, sig)
				sig.IsLastSectionAtOffset = true
				continue
			}

			continue
		case 3: // hex signature
			// this methos converts the format from CLAMAV signature to YARA
			sig.IsString = !regexpHexString.MatchString(value)
			sig.SigHash = translateSignatureToYARA(value)
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
	case ABSOLUTE_OFFSET:
		_, err = fmt.Sscanf(data, absoluteOffsetFormat, &offset)
		break
	case END_OF_FILE_MINUS:
		_, err = fmt.Sscanf(data, endOfFileFormat, &offset)
		break
	case ENTRY_POINT_PLUS:
		_, err = fmt.Sscanf(data, entryPointPlusFormat, &maxShift)
		break
	case ENTRY_POINT_MINUS:
		_, err = fmt.Sscanf(data, entryPointMinusFormat, &maxShift)
		break
	case START_SECTION_X:
		_, err = fmt.Sscanf(data, startSectionFormat, &offset, &maxShift)
		break
	case ENTIRE_SECTION_X:
		_, err = fmt.Sscanf(data, entireSectionFormat, &offset)
		break
	case START_LAST_SECTION:
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

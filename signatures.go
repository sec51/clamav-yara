package main

import (
	"regexp"
	"strconv"
	"time"
)

var (

	// EP+n = entry point plus n bytes (EP+0 for EP)
	entryPointPlusRegex         = regexp.MustCompile("^EP\\+[0-9]+")
	entryPointPlusFormat string = "EP+%d"

	//EP-n = entry point minus n bytes
	entryPointMinusRegex         = regexp.MustCompile("^EP\\-[0-9]+")
	entryPointMinusFormat string = "EP-%d"

	// Sx+n = start of section x’s (counted from 0) data plus n bytes
	startSectionRegex         = regexp.MustCompile("^S[0-9]+\\+[0-9]+")
	startSectionFormat string = "S%d+%d"

	// SEx = entire section x (offset must lie within section boundaries)
	entireSectionRegex         = regexp.MustCompile("^SE[0-9]+")
	entireSectionFormat string = "SE%d"

	// SL+n = start of last section plus n bytes
	lastSectionRegex         = regexp.MustCompile("^SL\\+[0-9]+")
	lastSectionFormat string = "SL+%d"

	// n
	absoluteOffsetRegex         = regexp.MustCompile("^[0-9]+")
	absoluteOffsetFormat string = "%d"

	// EOF-n
	endOfFileRegex         = regexp.MustCompile("^EOF-[0-9]+")
	endOfFileFormat string = "EOF-%d"
)

// this struct holds the NDB signature for each platform
type platformSigs struct {
	Platform        platform
	SigsNames       map[string]int // this map is used to lookup how many times the same name is used
	Sigs            []*signature
	LastGeneration  time.Time
	TotalSignatures int
}

// General signature struct
// It needs to have all those booleans because of the template rendering. Looking for a better way to handle this.
// Probably need to define a function on the template itself
type signature struct {
	MalwareName string
	SigHash     string
	IsString    bool // denotes whether a signature is a string or hex

	IsNdbSignature bool
	IsHdbSignature bool
	IsMdbSignature bool

	NdbSig *ndbSignature
	MdbSig *mdbSignature
	HdbSig *hdbSignature
}

func newPlatformSigs(pt platform) *platformSigs {
	sig := new(platformSigs)
	sig.Platform = pt
	sig.SigsNames = make(map[string]int)
	return sig
}

// convinient method to add signature to the array
// it also checks whether a malware name was already used, if so add increment to the name
func (ps *platformSigs) AddSigs(signature *signature) {

	// check if the malware name has already appeared - otherwise add it with increment zero
	if total, ok := ps.SigsNames[signature.MalwareName]; ok {
		increment := total + 1
		ps.SigsNames[signature.MalwareName] = increment
		signature.MalwareName = signature.MalwareName + "__" + strconv.Itoa(increment)
	} else {
		ps.SigsNames[signature.MalwareName] = 0
	}
	ps.Sigs = append(ps.Sigs, signature)

}

// Used to clone signatires so they can be added to different platform with slightly different flags set
func cloneSignature(originalSig *signature) *signature {
	newSignature := *originalSig
	return &newSignature
}

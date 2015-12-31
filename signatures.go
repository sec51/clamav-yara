package main

import (
	"regexp"
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
type platformNdbSigs struct {
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
	IsHsbSignature bool
	IsHdbSignature bool
	IsMdbSignature bool

	NdbSig *ndbSignature
}

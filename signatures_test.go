package main

import (
	"testing"
)

// the the regexp to match the signature types
func TestRegexp(t *testing.T) {

	matched := entryPointPlusRegex.MatchString("EP+0")
	if !matched {
		t.Fatal("Regexp kENTRY_POINT_PLUS did not match the case")
	}

	matched = entryPointMinusRegex.MatchString("EP-100")
	if !matched {
		t.Fatal("Regexp kENTRY_POINT_MINUS did not match the case")
	}

	matched = startSectionRegex.MatchString("S5+100")
	if !matched {
		t.Fatal("Regexp kSTART_SECTION_X did not match the case")
	}

	matched = entireSectionRegex.MatchString("SE5")
	if !matched {
		t.Fatal("Regexp kENTIRE_SECTION_X did not match the case")
	}

	matched = endOfFileRegex.MatchString("EOF-1000")
	if !matched {
		t.Fatal("Regexp kEND_OF_FILE_MINUS did not match the case")
	}

	matched = lastSectionRegex.MatchString("SL+1000")
	if !matched {
		t.Fatal("Regexp kSTART_LAST_SECTION did not match the case")
	}

	matched = absoluteOffsetRegex.MatchString("1000")
	if !matched {
		t.Fatal("Regexp kABSOLUTE_OFFSET did not match the case")
	}

}

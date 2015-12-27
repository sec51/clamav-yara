package main

import (
	"fmt"
	"testing"
)

func TestParseOffsetMaxShift(t *testing.T) {

	var offset, maxShift uint64
	var testCase string
	var leftOffset uint64 = 512
	var testMaxShift uint64 = 1024
	var defaultOffset uint64 = 0

	// #### EP+n
	testCase = fmt.Sprintf("EP+%d", testMaxShift) // "EP+1024"
	offset, maxShift = parseOffsetMaxShift(entryPointPlusFormat, testCase)
	if offset != defaultOffset || maxShift != testMaxShift {
		t.Errorf("Could not parse EP+n offset case: %s\n", testCase)
	}

	// #### EP-n
	testCase = fmt.Sprintf("EP-%d", testMaxShift) // "EP-1024"
	offset, maxShift = parseOffsetMaxShift(entryPointMinusFormat, testCase)
	if offset != defaultOffset || maxShift != testMaxShift {
		t.Errorf("Could not parse EP-n offset case: %s\n", testCase)
	}

	// #### Sx+n
	testCase = fmt.Sprintf("S%d+%d", leftOffset, testMaxShift) // "S512+1024"
	offset, maxShift = parseOffsetMaxShift(startSectionFormat, testCase)
	if offset != leftOffset || maxShift != testMaxShift {
		t.Errorf("Could not parse EP-n offset case: %s - got offset %d instead of %d and shift: %d instead of %d\n", testCase, offset, leftOffset, maxShift, testMaxShift)
	}

	// #### SEx
	testCase = "SE1" // "SE1"
	offset, maxShift = parseOffsetMaxShift(entireSectionFormat, testCase)
	if offset != 1 {
		t.Errorf("Could not parse SEx offset case: %s\n", testCase)
	}

	// #### SL+n
	testCase = fmt.Sprintf("SL+%d", testMaxShift) // "SL+1024"
	offset, maxShift = parseOffsetMaxShift(lastSectionFormat, testCase)
	if offset != defaultOffset || maxShift != testMaxShift {
		t.Errorf("Could not parse EP-n offset case: %s\n", testCase)
	}

}

func TestParseNdbSignatureRow(t *testing.T) {

	sample := `WIN.Trojan.Lolu:1:*:6e23692300000000ffffffff0400000022202f6600000000ffffffff0100000041000000ffffffff0100000043000000ffffffff07000000636d*6f72644c756369`
	sig := parseNdbSignatureRow(sample)

	if sig.MalwareName != "WIN.Trojan.Lolu" {
		t.Errorf("Malware name parsing error. Got %s instead of %s\n", sig.MalwareName, "WIN.Trojan.Lolu")
	}

	if sig.TargetType != PE_TARGET {
		t.Errorf("Malware target type parsing error. Got %d instead of %d\n", sig.TargetType, PE_TARGET)
	}

	if sig.Offset != 0 && sig.MaxShift != 0 && sig.OffsetType != ANY_OFFSET {
		t.Error("Malware Offset detection error. This supposed to be ANY OFFSET")
	}

	if sig.SigHash != "6E23692300000000FFFFFFFF0400000022202F6600000000FFFFFFFF0100000041000000FFFFFFFF0100000043000000FFFFFFFF07000000636D[-]6F72644C756369" {
		t.Error("Malware signature detection error")
	}

}

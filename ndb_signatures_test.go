package main

import (
	"fmt"
	"io/ioutil"
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
	offset, maxShift = parseOffsetMaxShift(ENTRY_POINT_PLUS, entryPointPlusFormat, testCase)
	if offset != defaultOffset || maxShift != testMaxShift {
		t.Errorf("Could not parse EP+n offset case: %s\n", testCase)
	}

	// #### EP-n
	testCase = fmt.Sprintf("EP-%d", testMaxShift) // "EP-1024"
	offset, maxShift = parseOffsetMaxShift(ENTRY_POINT_MINUS, entryPointMinusFormat, testCase)
	if offset != defaultOffset || maxShift != testMaxShift {
		t.Errorf("Could not parse EP-n offset case: %s\n", testCase)
	}

	// #### Sx+n
	testCase = fmt.Sprintf("S%d+%d", leftOffset, testMaxShift) // "S512+1024"
	offset, maxShift = parseOffsetMaxShift(START_SECTION_X, startSectionFormat, testCase)
	if offset != leftOffset || maxShift != testMaxShift {
		t.Errorf("Could not parse EP-n offset case: %s - got offset %d instead of %d and shift: %d instead of %d\n", testCase, offset, leftOffset, maxShift, testMaxShift)
	}

	// #### SEx
	testCase = "SE1" // "SE1"
	offset, maxShift = parseOffsetMaxShift(ENTIRE_SECTION_X, entireSectionFormat, testCase)
	if offset != 1 {
		t.Errorf("Could not parse SEx offset case: %s\n", testCase)
	}

	// #### SL+n
	testCase = fmt.Sprintf("SL+%d", testMaxShift) // "SL+1024"
	offset, maxShift = parseOffsetMaxShift(START_LAST_SECTION, lastSectionFormat, testCase)
	if offset != defaultOffset || maxShift != testMaxShift {
		t.Errorf("Could not parse EP-n offset case: %s\n", testCase)
	}

}

func TestParseNdbSignatureRow(t *testing.T) {

	sample := `WIN.Trojan.Lolu:1:*:6e23692300000000ffffffff0400000022202f6600000000ffffffff0100000041000000ffffffff0100000043000000ffffffff07000000636d*6f72644c756369`
	sig := parseNdbSignatureRow(sample)

	if sig.MalwareName != "WIN_Trojan_Lolu" {
		t.Errorf("Malware name parsing error. Got %s instead of %s\n", sig.MalwareName, "WIN_Trojan_Lolu")
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

func TestParseNDBSignatures(t *testing.T) {
	// Read all data
	data, err := ioutil.ReadFile("daily_test.cvd")
	if err != nil {
		t.Fatal(err)
	}

	files, err := ExtractFiles(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) == 0 {
		t.Fatal("There should be at least 1 definition file after exracting the data")
	}

	// rename to singular
	file := files[0]

	pt := ParseNDBSignatures(file.Name, file.Data)

	for _, ndbSig := range pt {
		if len(ndbSig.Sigs) == 0 {
			t.Errorf("Failed to parse signatures for platform: %s\n", ndbSig.Platform.String())
		}

		if err := writeRules(ndbSig); err != nil {
			t.Fatal(err)
		}

	}

}

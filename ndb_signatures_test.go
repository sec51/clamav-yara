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
	offset, maxShift = parseOffsetMaxShift(kENTRY_POINT_PLUS, entryPointPlusFormat, testCase)
	if offset != defaultOffset || maxShift != testMaxShift {
		t.Errorf("Could not parse EP+n offset case: %s\n", testCase)
	}

	// #### EP-n
	testCase = fmt.Sprintf("EP-%d", testMaxShift) // "EP-1024"
	offset, maxShift = parseOffsetMaxShift(kENTRY_POINT_MINUS, entryPointMinusFormat, testCase)
	if offset != defaultOffset || maxShift != testMaxShift {
		t.Errorf("Could not parse EP-n offset case: %s\n", testCase)
	}

	// #### Sx+n
	testCase = fmt.Sprintf("S%d+%d", leftOffset, testMaxShift) // "S512+1024"
	offset, maxShift = parseOffsetMaxShift(kSTART_SECTION_X, startSectionFormat, testCase)
	if offset != leftOffset || maxShift != testMaxShift {
		t.Errorf("Could not parse EP-n offset case: %s - got offset %d instead of %d and shift: %d instead of %d\n", testCase, offset, leftOffset, maxShift, testMaxShift)
	}

	// #### SEx
	testCase = "SE1" // "SE1"
	offset, maxShift = parseOffsetMaxShift(kENTIRE_SECTION_X, entireSectionFormat, testCase)
	if offset != 1 {
		t.Errorf("Could not parse SEx offset case: %s\n", testCase)
	}

	// #### SL+n
	testCase = fmt.Sprintf("SL+%d", testMaxShift) // "SL+1024"
	offset, maxShift = parseOffsetMaxShift(kSTART_LAST_SECTION, lastSectionFormat, testCase)
	if offset != defaultOffset || maxShift != testMaxShift {
		t.Errorf("Could not parse EP-n offset case: %s\n", testCase)
	}

}

func TestParseNdbSignatureRow(t *testing.T) {

	signature := new(signature)

	sample := `WIN.Trojan.Lolu:1:*:6e23692300000000ffffffff0400000022202f6600000000ffffffff0100000041000000ffffffff0100000043000000ffffffff07000000636d*6f72644c756369`
	sig := parseNdbSignatureRow(sample, signature)

	if signature.MalwareName != "WIN_Trojan_Lolu" {
		t.Errorf("Malware name parsing error. Got %s instead of %s\n", signature.MalwareName, "WIN_Trojan_Lolu")
	}

	if sig.TargetType != kPE_TARGET {
		t.Errorf("Malware target type parsing error. Got %d instead of %d\n", sig.TargetType, kPE_TARGET)
	}

	if sig.Offset != 0 && sig.MaxShift != 0 && sig.OffsetType != kANY_OFFSET {
		t.Error("Malware Offset detection error. This supposed to be ANY OFFSET")
	}

	if signature.SigHash != "6E23692300000000FFFFFFFF0400000022202F6600000000FFFFFFFF0100000041000000FFFFFFFF0100000043000000FFFFFFFF07000000636D[-]6F72644C756369" {
		t.Error("Malware signature detection error")
	}

	sample = "W32.Troxa:1:EP+0:e990fcffff"
	sig = parseNdbSignatureRow(sample, signature)

	if sig.OffsetType != kENTRY_POINT_PLUS {
		t.Fatal("Signatures should be of type ENTRY_POINT_PLUS")
	}

}

func TestParseNDBSignatures(t *testing.T) {
	// Read all data
	data, err := ioutil.ReadFile("main_test.cvd")
	if err != nil {
		t.Fatal(err)
	}

	files, err := extractFiles(data, MAIN_DEFINITION)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) == 0 {
		t.Fatal("There should be at least 1 definition file after exracting the data")
	}

	// rename to singular
	file := files[0]

	pt := parseNDBSignatures(file.Name, file.Data)

	for _, ndbSig := range pt {
		if len(ndbSig.Sigs) == 0 {
			t.Errorf("Failed to parse signatures for platform: %s\n", ndbSig.Platform.String())
		}

		if err := writeRules(ndbSig, MAIN_DEFINITION, kNDB_EXTENSION); err != nil {
			t.Fatal(err)
		}

	}

}

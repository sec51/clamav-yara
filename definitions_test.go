package main

import (
	"fmt"
	"io/ioutil"
	"testing"
)

// Test the initialization of the definition manager
func TestNewDefinitionsManager(t *testing.T) {
	manager, err := NewDefinitionManager()
	if err != nil {
		t.Fatal(err)
	}

	if manager == nil {
		t.Fatal("Failed to initialize the definitions download manager")
	}

	// fmt.Println(manager.EtagMain)
	// fmt.Println(manager.EtagDaily)
	// fmt.Println(manager.PublicKeyData.Type)

	fmt.Println("OK. DefinitionManager init SUCCESS")
}

// Test the parsing of the Clamav virus DB header
func TestParseHeader(t *testing.T) {
	// Read all data
	data, err := ioutil.ReadFile("main_test.cvd")
	if err != nil {
		t.Fatal(err)
	}

	def, err := parseHeader(data)
	if err != nil {
		t.Fatal(err)
	}

	if def.Level != 60 {
		t.Errorf("Parsing Level header, expected level 60, got %s\n", def.Level)
	}

	if def.TotalSignatures != 2424225 {
		t.Errorf("Parsing TotalSignatures header, expected level 2424225, got %s\n", def.TotalSignatures)
	}

	if def.Version != 55 {
		t.Errorf("Parsing TotalSignatures header, expected level 55, got %s\n", def.Version)
	}

	if def.MD5Hash == "" {
		t.Error("Parsing MD5 hash header and got it empty")
	}

	if def.Signature == "" {
		t.Error("Parsing Signature header and got it empty")
	}

	files, err := extractFiles(data, MAIN_DEFINITION)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) == 0 {
		t.Fatal("Could not extract a single file")
	}

	fmt.Println("OK. Header parsing SUCCESS")

}

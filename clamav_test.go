package main

import (
	//"fmt"
	"testing"
)

func TestTranslateSignatureToYARA(t *testing.T) {

	sample := `6e23692300000000ffffffff0400000022202f6600000000ffffffff0100000041000000ffffffff0100000043000000ffffffff07000000636d*6f72644c756369`
	result := translateSignatureToYARA(sample)
	if result != "6E23692300000000FFFFFFFF0400000022202F6600000000FFFFFFFF0100000041000000FFFFFFFF0100000043000000FFFFFFFF07000000636D[-]6F72644C756369" {
		t.Fatal("Could not translate ClamAV signature to YARA - Missing conversion of wildcard: *")
	}

	sample = `2f54797065{-20}2f416374696f6e{-10}2f53{-20}2f476f546f(45|52){-10}2f46{-10}2866696c653a`
	result = translateSignatureToYARA(sample)
	if result != "2F54797065[-20]2F416374696F6E[-10]2F53[-20]2F476F546F(45|52)[-10]2F46[-10]2866696C653A" {
		t.Fatal("Could not translate ClamAV signature to YARA - Missing conversion of JUMPS os UNBOUNDED JUMPS")
	}

}

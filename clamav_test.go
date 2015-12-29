package main

import (
	//"fmt"
	"strings"
	"testing"
)

func TestTranslateSignatureToYARA(t *testing.T) {

	sample := `6e23692300000000ffffffff0400000022202f6600000000ffffffff0100000041000000ffffffff0100000043000000ffffffff07000000636d*6f72644c756369`
	result := translateSignatureToYARA(sample)
	//fmt.Println(result)
	if result != "6E23692300000000FFFFFFFF0400000022202F6600000000FFFFFFFF0100000041000000FFFFFFFF0100000043000000FFFFFFFF07000000636D[-]6F72644C756369" {
		t.Fatal("Could not translate ClamAV signature to YARA - Missing conversion of wildcard: *")
	}

	sample = `2f54797065{-20}2f416374696f6e{-10}2f53{-20}2f476f546f(45|52){-10}2f46{-10}2866696c653a`
	result = translateSignatureToYARA(sample)
	//fmt.Println(result)
	if result != "2F54797065[0-20]2F416374696F6E[0-10]2F53[0-20]2F476F546F(45|52)[0-10]2F46[0-10]2866696C653A" {
		t.Fatal("Could not translate ClamAV signature to YARA - Missing conversion of JUMPS or UNBOUNDED JUMPS")
	}

	sample = `57006f0072006b0062006f006f006b;00????????0f0004f0????????????!(0a|0a)!(f0|f0)08000000;0f0003f0????????0f0004f0????????010009f010000000{18}!(0a|0a)!(f0|f0)08000000`
	result = translateSignatureToYARA(sample)
	//fmt.Println(result)
	//fmt.Println("57006f0072006b0062006f006f006b;00????????0f0004f0????????????*08000000;0f0003f0????????0f0004f0????????010009f010000000{18}*08000000")
	if result != strings.ToUpper("57006f0072006b0062006f006f006b;00????????0f0004f0????????????*08000000;0f0003f0????????0f0004f0????????010009f010000000[18]*08000000") {
		t.Fatal("Could not translate ClamAV signature to YARA - Missing conversion of NOT OR")
	}

}

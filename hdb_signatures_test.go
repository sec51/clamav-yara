package main

import (
	"testing"
)

func TestParseHdbSignatureRow(t *testing.T) {
	signature := new(signature)
	sample := "e11c2aff804ca144a3e49c42d6ac5783:1006:Exploit.CVE_2012_0779"
	sig := parseHdbSignatureRow(sample, signature)

	if sig.Size != 1006 {
		t.Fatal("Error parsing HDB or HSB signature length")
	}

	if signature.SigHash != "e11c2aff804ca144a3e49c42d6ac5783" {
		t.Fatal("Error parsing HDB or HSB signature hash")
	}
}

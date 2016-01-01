package main

import (
	"testing"
)

func TestParseMdbSignatureRow(t *testing.T) {
	signature := new(signature)
	sample := "190464:3b2769dfce52e9ebe8e34ed89a09e8c5:Win.Adware.Hotbar-9174"
	sig := parseMdbSignatureRow(sample, signature)

	if sig.PeSectionSize != 190464 {
		t.Fatal("Error parsing MDB or MSB PE section length")
	}

	if signature.SigHash != "3b2769dfce52e9ebe8e34ed89a09e8c5" {
		t.Fatal("Error parsing MDB or MSB PE section signature hash")
	}
}

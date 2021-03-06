package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

type signatureTarget uint16
type platform uint8

const (

	// signatureTarget
	kANY_TARGET signatureTarget = 0 + iota
	kPE_TARGET
	kOLE2_TARGET
	kHTML_TARGET
	kMAIL_TARGET
	kGRAPHIC_TARGET
	kELF_TARGET
	kASCII_TARGET
	kUNUSED_TARGET
	kMACH_O_TARGET
	kPDF_TARGET
	kFLASH_TARGET
	kJAVA_TARGET
)

const (
	// platform
	kWIN_PLATFORM platform = 0 + iota
	kLINUX_PLATFORM
	kOSX_PLATFORM
	kANY_PLATFORM
)

const (
	// OFFSET TYPE
	kANY_OFFSET = 0 + iota
	kABSOLUTE_OFFSET
	kEND_OF_FILE_MINUS
	kENTRY_POINT_PLUS
	kENTRY_POINT_MINUS
	kSTART_SECTION_X
	kENTIRE_SECTION_X
	kSTART_LAST_SECTION
)

var (
	// matched strings like: !(0a|7b)!(1f|3c)
	regexpHexString      = regexp.MustCompile("^[0-9a-fA-F]{4}") // this is really a weak way of testing whether we need to use string or hex in YARA
	regexpNotOrSignature = regexp.MustCompile("(!\\([0-9a-fA-F]+(\\|?[0-9a-fA-F]+)*\\))+")
	//regexpOrSignature    = regexp.MustCompile("(\\([0-9a-fA-F]+(\\|?[0-9a-fA-F]+)*\\))+")
	rulesFolder = "rules"
)

func (p platform) String() string {
	switch p {
	case kWIN_PLATFORM:
		return "windows"
	case kLINUX_PLATFORM:
		return "linux"
	case kOSX_PLATFORM:
		return "osx"
	case kANY_PLATFORM:
		return "any"
	default:
		return "unknown"
	}

}

// splits a file into rows via /n
func parseFile(headerName string, data string) []string {
	fileRows := strings.Split(data, "\n")
	if len(fileRows) == 0 {
		fmt.Println("Definition file", headerName, "has no rows")
	}
	return fileRows
}

// this function modifies the signature format from ClamAV to YARA
// TODO:
/*

	THESE SIGNATURE FORMATS SEEMS NOT TO BE IN USE BY CLAMAV ALTHOUGH THEY ARE IN THE DOCS (NEEDS FURTHER INVESTIGATION)

	Multi-byte fixed length alternates: NEED TO UNDERSTAND BETTER AND SEE SOME EXAMPLES
		(aaaa|bbbb|cccc|...) or !(aaaa|bbbb|cccc|...)
		Match a member from a set of multi-byte alternates [aaaa, bbbb, cccc, ...] of n-length.
			– All set members must be the same length.
			– Negationoperationcanbeappliedtomatchanynon-member,assumed to be n-bytes in length (clamav-0.98.2).
			– Signature modifiers and wildcards cannot be applied.

	(B)
		Match word boundary (including file boundaries). [In YARA should be: \b]

	(L)
		Match CR, CRLF or file boundaries. [In YARA should be: \r OR \r\n {missing the file boundaries}]

	(W)
		Match a non-alphanumeric character. [In YARA should be: \W AND \D] non word AND non digit

*/
func translateSignatureToYARA(sigHash string) string {

	// NIBBLE MATCHING: same for both => a? or ?? or ?a
	// NOTHING TO DO HERE

	// WILDCARD * to [-]
	if strings.Contains(sigHash, "*") {
		sigHash = strings.Replace(sigHash, "*", "[-]", -1)
	}

	// JUMPS:	{LOWER-HIGHER}	to [LOWER-HIGHER] 	=> we need to substitutde the parenthesis => OK
	// UNBOUNDED JUMPS: {10-}   to [10-]			=> we need to substitutde the parenthesis => OK
	// we need to sanitize the case {-n}, yara does not suport it, therefore translate it to {0-n}
	if strings.Contains(sigHash, "{-") {
		sigHash = strings.Replace(sigHash, "{-", "{0-", -1)
	}

	if strings.Contains(sigHash, "{") {
		sigHash = strings.Replace(sigHash, "{", "[", -1)
		sigHash = strings.Replace(sigHash, "}", "]", -1)
	}

	// OR: (aa|bb|cc|..) to (aa|bb|cc|..)
	// NOTHING TO DO HERE

	// NOT OR: !(aa|bb|cc|..) to (aa|bb|cc|..) with NOT in the condition section (complicates the generation of YARA signatures)
	// We convert it to ANY (*) until we find a solution. This may affect negatively the matchjig of malware in terms of performance and detection
	sigHash = regexpNotOrSignature.ReplaceAllString(sigHash, "*")

	return strings.ToUpper(sigHash)

}

// This method is used to write the final yara rule files
// It automatically creates all 3: Win, Linux, OS X
func writeRules(pt *platformSigs, fileType definitionType, signatureType definitionExtensionType) error {

	// parse the template
	tpl, err := template.ParseFiles("yara.tpl")
	if err != nil {
		return err
	}

	// cerate a buffer to store the in memory template
	var buffer bytes.Buffer

	// process the data
	err = tpl.Execute(&buffer, pt)
	if err != nil {
		fmt.Printf("Creation of rules for platform %s failed with error %s\n:", pt.Platform.String(), err)
		return err
	}

	// write the template to disk

	fileName := fileType.String() + "_" + pt.Platform.String() + ".yara"

	switch signatureType {
	case kHDB_EXTENSION:
		fileName = "file_" + fileName
	}

	fullPath := filepath.Join(rulesFolder, fileName)

	err = ioutil.WriteFile(fullPath, buffer.Bytes(), 0644)

	return err

}

// YARA does not support dots, dash on the malware name, so we need to sanitize the string
func sanitizeMalwareName(malware string) string {

	malware = strings.Replace(malware, ".", "_", -1)
	malware = strings.Replace(malware, "-", "_", -1)

	return malware

}

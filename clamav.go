package main

import (
	"fmt"
	"strings"
)

type signatureTarget uint16
type platform uint8

const (

	// signatureTarget
	ANY_TARGET signatureTarget = 0 + iota
	PE_TARGET
	OLE2_TARGET
	HTML_TARGET
	MAIL_TARGET
	GRAPHIC_TARGET
	ELF_TARGET
	ASCII_TARGET
	UNUSED_TARGET
	MACH_O_TARGET
	PDF_TARGET
	FLASH_TARGET
	JAVA_TARGET

	// platform
	WIN_PLATFORM platform = 0 + iota
	LINUX_PLATFORM
	OSX_PLATFORM

	// OFFSET TYPE
	ANY_OFFSET = 0 + iota
	ABSOLUTE_OFFSET
	END_OF_FILE_MINUS
	ENTRY_POINT_PLUS
	ENTRY_POINT_MINUS
	START_SECTION_X
	ENTIRE_SECTION_X
	START_LAST_SECTION
)

// splits a file into rows via /n
func parseFile(headerName string, data string) []string {
	fileRows := strings.Split(data, "\n")
	if len(fileRows) == 0 {
		fmt.Println("Definition file", headerName, "has no rows")
	}
	return fileRows
}

// this function modifies the signature format from ClamAV to YARA
//
func translateSignatureToYARA(sigHash string) string {

	// NIBBLE MATCHING: same for both => a? or ?? or ?a
	// NOTHING TO DO HERE

	// WILDCARD * to [-]
	if strings.Contains(sigHash, "*") {
		sigHash = strings.Replace(sigHash, "*", "[-]", -1)
	}

	// JUMPS:	{LOWER-HIGHER}	to [LOWER-HIGHER] 	=> we need to substitutde the parenthesis => OK
	// UNBOUNDED JUMPS: {10-}   to [10-]			=> we need to substitutde the parenthesis => OK
	if strings.Contains(sigHash, "{") {
		sigHash = strings.Replace(sigHash, "{", "[", -1)
		sigHash = strings.Replace(sigHash, "}", "]", -1)
	}

	// OR: (aa|bb|cc|..) to (aa|bb|cc|..)
	// NOTHING TO DO HERE

	// NOT OR: !(aa|bb|cc|..) to (aa|bb|cc|..) with NOT in the condition section (complicates the generation of YARA signatures)
	// SKIPPED FOR NOW until I find a proper way to do it

	return strings.ToUpper(sigHash)

}

package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"golang.org/x/crypto/openpgp/armor"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// FORMATS:
// *.hsb => HashString:FileSize:MalwareName - (HashString can be both SHA1 and SHA256 - need to distinguish based on the length of the string)
// *.mdb => PESectionSize:PESectionHash:MalwareName - a hash signature for a specific section in a PE file. Hash is MD5
// *.msb => PESectionSize:PESectionHash:MalwareName - a hash signature for a specific section in a PE file. Hash can be SHA1 and SHA256
// *.ldb => SignatureName;TargetDescriptionBlock;LogicalExpression;Subsig0;Subsig1;Subsig2;... - allow combining of multiple signatures in extended format using
// 			logical operators. They can provide both more detailed and flexible pattern
// 			matching.
// *.ndb => MalwareName:TargetType:Offset:HexSignature[:MinFL:[MaxFL]]
//
/* TargetType is one of the following numbers specifying the type of the target file:
• 0 = 		any file
• 1 = 		Portable Executable, both 32- and 64-bit.
• 2 = 		file inside OLE2 container (e.g. image, embedded executable, VBA
			script). The OLE2 format is primarily used by MS Office and MSI installation
			files.
• 3 = 		HTML (normalized: whitespace transformed to spaces, tags/tag attributes
			normalized, all lowercase), Javascript is normalized too: all strings
			are normalized (hex encoding is decoded), numbers are parsed and normalized,
			local variables/function names are normalized to ’n001’ format, argument
			to eval() is parsed as JS again, unescape() is handled, some simple JS
			packers are handled, output is whitespace normalized.
• 4 = 		Mail file
• 5 = 		Graphics
• 6 = 		ELF
• 7 = 		ASCII text file (normalized)
• 8 = 		Unused
• 9 = 		Mach-O files
• 10 = 		PDF files
• 11 = 		Flash files
• 12 = 		Java class files

Offset is an asterisk or a decimal number n possibly combined with a special modifier:
• * = 		any
• n = 		absolute offset
• EOF-n = 	end of file minus n bytes

Signatures for PE, ELF and Mach-O files additionally support:
• EP+n = 	entry point plus n bytes (EP+0 for EP)
• EP-n = 	entry point minus n bytes
• Sx+n = 	start of section x’s (counted from 0) data plus n bytes
• SEx  = 	entire section x (offset must lie within section boundaries)
• SL+n = 	start of last section plus n bytes
*/
// *.fp => 	MD5 signatures for whitelisting files
// *.sfp => SHA1 and SHA256 signatures for whitelisting files

// It seems that Clamav does not offer HTTPS for downloading of the definitions.
// This means the files need to be checked against the signature
// Need to look into the signature format fore the CVD file! Seems to be using: plain = cipher^e mod n

// ===================== YARA vs ClamAV SIGNATURE formats
// NIBBLE MATCHING: same for both => a? or ?? os ?a => OK
// WILDCARD *: [-] vs * => OK
// JUMPS:	[LOWER-HIGHER]	vs {LOWER-HIGHER} 	=> we need to substitutde the parenthesis => OK
// UNBOUNDED JUMOS: [10-]   vs {10-}			=> we need to substitutde the parenthesis => OK
// OR: (aa|bb|cc|..) vs (aa|bb|cc|..) => OK
// NOT OR: (aa|bb|cc|..) with NOT in the condition section (complicates the generation of YARA signatures) vs !(aa|bb|cc|..) => SKIPPED FOR NOW
// ELF, PE: specific target type vs entrypoint (entrypoint is deprecated in favour of an external module.
// 			I find this quite risky in terms of memory leaks...) => SKIPPED FOR NOW

const (
	MAIN_DATABASE_URL  = "http://database.clamav.net/main.cvd"
	DAILY_DATABASE_URL = "http://database.clamav.net/daily.cvd"
)

// Created once, this object allows to download the ClamAV definitions from a specific URL (at the moment hard coded)
type DefinitionsManager struct {
	httpCLient    http.Client  // the HTTP client for downloading the definitions
	EtagMain      string       // etag of the main DB was downloaded
	EtagDaily     string       // etag of the daily DB was downloaded
	PublicKeyData *armor.Block // TODO: the Clamav public key which is read from the local verification.key
}

// This is the struct for holding the ClamAV file header information
type definition struct {
	MD5Hash         string // md5 hash of the data
	Signature       string // signature which needs to be verified
	Version         int    // version of the DB
	TotalSignatures int64  // total amount of signatures in the file
	Level           int    // functionality level
	Data            string // the data itself (contains all the signatures, new line separated) -Format: mdb
}

// Initialize a new DefinitionManager
func NewDefinitionManager() (*DefinitionsManager, error) {

	// new instance of the manager
	manager := new(DefinitionsManager)

	// open the public key file
	verificationKeyFileReader, err := os.Open("verification.key")
	if err != nil {
		return nil, err
	}

	// close the file once we are done here
	defer verificationKeyFileReader.Close()

	// instantiate a new File Reader
	keyReader := bufio.NewReader(verificationKeyFileReader)

	// if we got here then the sha256 match, we can proceed
	block, err := armor.Decode(keyReader)
	if err != nil {
		return nil, err
	}

	manager.PublicKeyData = block
	manager.httpCLient = http.Client{}

	return manager, nil

}

// TODO: implement signature verification
func (m *DefinitionsManager) VerifyFile(file string) bool {
	return true
}

// Download the virus database based on the last modified
// This method blocks
func (m *DefinitionsManager) DownloadDefinitions(url string, etag string) error {

	req, err := http.NewRequest("GET", url, nil)

	// Add the header if the etag is not mpety
	if etag != "" {
		req.Header.Add("If-None-Match", etag)
	}

	// make the request
	resp, err := m.httpCLient.Do(req)
	if err != nil {
		return err
	}

	// defer the closing of the body
	defer resp.Body.Close()

	//  check if the response was 304: Not modified => return, nothing to do here
	if resp.StatusCode == 304 {
		return nil
	}

	// add the Etag to the data
	if url == MAIN_DATABASE_URL {
		m.EtagMain = resp.Header.Get("Etag")
	}

	if url == DAILY_DATABASE_URL {
		m.EtagDaily = resp.Header.Get("Etag")
	}

	return nil

}

// Parse the clamav virus database header
// ClamAV-VDB:build time:version:number of signatures:functionality level required:MD5 checksum:digital signature:builder name:build time (sec)
// This is present in the first 512 btes of the file
// The rest is a TAR GZ encoded file
func parseHeader(data []byte) (*definition, error) {

	// init the definition
	def := new(definition)

	// convert to string so we can parse it more easily
	dataString := string(data[:512])

	tokens := strings.Split(dataString, ":")

	if len(tokens) != 9 {
		return nil, errors.New(fmt.Sprintf("After parsing the header we expected 9 tokens instead we've got %d\n", len(tokens)))
	}

	// Version
	version, err := strconv.Atoi(tokens[2])
	if err != nil {
		return nil, err
	}
	// Total Signatures
	totalSigs, err := strconv.ParseInt(tokens[3], 10, 64)
	if err != nil {
		return nil, err
	}
	// Version
	level, err := strconv.Atoi(tokens[4])
	if err != nil {
		return nil, err
	}

	def.Version = version
	def.TotalSignatures = totalSigs
	def.Level = level
	def.MD5Hash = tokens[5]
	def.Signature = tokens[6]

	return def, nil

}

// Extract the file tar.gz
func ExtractFiles(data []byte) error {

	// extract the data only and cut the header off
	tarGzip := data[512:]

	// create the buffer from the tarGzip data
	gzipBuffer := bytes.NewBuffer(tarGzip)

	// uncompress
	gzipReader, err := gzip.NewReader(gzipBuffer)
	if err != nil {
		return err
	}

	tarReader := tar.NewReader(gzipReader)

	// Create a new buffer for extracting the file
	var fileBuffer bytes.Buffer

	// Iterate through the files in the archive.
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			// end of tar archive
			break
		}
		if err != nil {
			return err
		}
		//fmt.Printf("Contents of %s:\n", header.Name)

		// TODO: extract the files
		// if _, err := io.Copy(os.Stdout, tr); err != nil {
		// 	log.Fatalln(err)
		// }
		//fmt.Println()

		// reset the buffer
		fileBuffer.Reset()

		// read the file into the buffer
		if _, err := io.Copy(&fileBuffer, tarReader); err != nil {
			fmt.Printf("Could not untar %s: %s\n", header.Name, err)
			continue
		}

		switch {
		case strings.Contains(header.Name, ".ndb"):
			//ParseNDBSignatures(header.Name, fileBuffer.String())
			break
		default:
			fmt.Printf("ClamAV file format %s not supported at the moment\n", header.Name)
		}
	}

	return nil

}

package main

import (
	"log"
	"time"
)

// downaloads the definitions every: 4 hours
var kDOWNLOAD_AFTER = 4 * time.Hour

func main() {

	manager, err := NewDefinitionManager()
	if err != nil {
		log.Fatal(err)
	}

	// First download when the program starts
	downloadDefinitions(manager)

	// repeatedly download the definitions and process them
	for range time.Tick(kDOWNLOAD_AFTER) {
		downloadDefinitions(manager)
	}
}

// helper function to download both main and daily definitions
func downloadDefinitions(manager *DefinitionsManager) {
	var err error
	if err = manager.DownloadDefinitions(MAIN_DEFINITION); err != nil {
		log.Fatal(err)
	}

	if err = manager.DownloadDefinitions(DAILY_DEFINITION); err != nil {
		log.Fatal(err)
	}
}

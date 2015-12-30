package main

import (
	"log"
)

func main() {

	manager, err := NewDefinitionManager()
	if err != nil {
		log.Fatal(err)
	}

	if err = manager.DownloadDefinitions(MAIN_DEFINITION); err != nil {
		log.Fatal(err)
	}

	if err = manager.DownloadDefinitions(DAILY_DEFINITION); err != nil {
		log.Fatal(err)
	}

}

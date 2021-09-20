package app

import (
	"eccs/utils"
	"log"
)

// Update creates a new client and calls Update through the client
func Update(userAT, objectID, filename, associatedData string, stdin bool) error {
	//Determine whether to read data from file or stdin
	plaintext, err := readInput(filename, stdin)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Update failed at readInput"), err)
	}

	// Create client
	client, err := NewClient(userAT)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Update failed at NewClient"), err)
	}

	// Call Encryptonize and update the object
	err = client.Update(objectID, plaintext, []byte(associatedData))
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Update failed at Update"), err)
	}

	return nil
}

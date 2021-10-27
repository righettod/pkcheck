package main

import (
	"encoding/pem"
	"os"
	"sync"
	"testing"
)

//An array isn't immutable by nature; you can't make it constant.
//See https://stackoverflow.com/a/13137568
//See https://golangbyexample.com/constant-array-golang/
var testPrivateKeys = []string{"./test-resources/pk-key-ec.txt", "./test-resources/pk-key-rsa.txt"}

func loadKey(keyFile string) (keyBytes []byte, err error) {
	var keyContentBytes, errKey = os.ReadFile(keyFile)
	if errKey == nil {
		return keyContentBytes, nil
	} else {
		return nil, errKey
	}
}

func TestPassphraseRecovered(t *testing.T) {
	//Define the valid passphrase
	var expectedPassphrase string = "123456"
	//Setup communication channel
	comChannel := make(chan string, 1)
	var waitGroup sync.WaitGroup
	//Test each keys
	for _, keyFile := range testPrivateKeys {
		//Load and decode current key
		keyBytes, err := loadKey(keyFile)
		if err != nil {
			t.Errorf("Cannot load key file '%v'.", keyFile)
		}
		block, _ := pem.Decode(keyBytes)
		if block == nil {
			t.Errorf("Cannot decode key file '%v'.", keyFile)
		}
		waitGroup.Add(1)
		//Test passphrase recovery for the current key
		probePassphrase(expectedPassphrase, block, comChannel, &waitGroup)
		//Verify test execution results
		if len(comChannel) == 1 {
			var p string = <-comChannel
			if p != expectedPassphrase {
				t.Fatalf("Incorrect passphrase recovered for key file '%v'.", keyFile)
			} else {
				t.Logf("Correct passphrase recovered for key file '%v'.", keyFile)
			}
		} else {
			t.Fatalf("Passphrase not recovered for key file '%v'.", keyFile)
		}
	}
}

func TestPassphraseNotRecovered(t *testing.T) {
	//Define an invalid passphrase
	var incorrectPassphrase string = "INVALID"
	//Setup communication channel
	comChannel := make(chan string, 1)
	var waitGroup sync.WaitGroup
	//Test each keys
	for _, keyFile := range testPrivateKeys {
		//Load and decode current key
		keyBytes, err := loadKey(keyFile)
		if err != nil {
			t.Errorf("Cannot load key file '%v'.", keyFile)
		}
		block, _ := pem.Decode(keyBytes)
		if block == nil {
			t.Errorf("Cannot decode key file '%v'.", keyFile)
		}
		waitGroup.Add(1)
		//Test passphrase recovery for the current key
		probePassphrase(incorrectPassphrase, block, comChannel, &waitGroup)
		//Verify test execution results
		if len(comChannel) != 0 {
			t.Fatalf("A passphrase was recovered for key file '%v' even using an incorrect passphrase '%v'.", keyFile, incorrectPassphrase)
		} else {
			t.Logf("Correct behavior, passphrase not recovered, for key file '%v'.", keyFile)
		}
	}
}

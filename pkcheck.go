/*
This package is a sample program brute forcing the passphrase of a private key.
*/
package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

const exitErrorCode int = 1
const exitKeyNotProtectedCode int = 2
const enableDerivationOptionName string = "--enable-derivation"

func main() {
	fmt.Println("[+] check parameters...")
	if len(os.Args) < 3 {
		color.Red("Bad syntax!")
		fmt.Printf("Call syntax:\n\t%v {PASSPHRASE_DICTIONARY_FILE_PATH} {KEY_PEM_FILE_PATH} [%v]\n", filepath.Base(os.Args[0]), enableDerivationOptionName)
		fmt.Printf("Call example:\n\t%v passphrases.txt pk-key-ec.txt\n", filepath.Base(os.Args[0]))
		fmt.Printf("\t%v passphrases.txt pk-key-ec.txt %v\n", filepath.Base(os.Args[0]), enableDerivationOptionName)
		os.Exit(exitErrorCode)
	}
	var passphraseDictFile string = os.Args[1]
	var keyFile string = os.Args[2]
	if _, err := os.Stat(passphraseDictFile); err != nil {
		color.Red("Passphrase dictionary file do not exists!")
		os.Exit(exitErrorCode)
	}
	if _, err := os.Stat(keyFile); err != nil {
		color.Red("Key file do not exists!")
		os.Exit(exitErrorCode)
	}
	fmt.Println("[+] Load passphrases and key...")
	var passphraseContentBytes, errPassphrase = os.ReadFile(passphraseDictFile)
	if errPassphrase != nil {
		color.Red("Cannot load passphrase dictionary content!")
		os.Exit(exitErrorCode)
	}
	var passphrases []string = strings.Split(string(passphraseContentBytes[:]), "\n")
	fmt.Printf("%v passphrases loaded.\n", len(passphrases))
	var keyContentBytes, errKey = os.ReadFile(keyFile)
	if errKey != nil {
		color.Red("Cannot load key content!")
		os.Exit(exitErrorCode)
	}
	block, _ := pem.Decode(keyContentBytes)
	if block == nil {
		color.Red("Cannot decode the key!")
		os.Exit(exitErrorCode)
	}
	var validPrivateKeyHeader = regexp.MustCompile(`^[A-Z]*\s?PRIVATE KEY$`)
	if !validPrivateKeyHeader.MatchString(block.Type) {
		color.Red("Key is not a private key! (%v)", block.Type)
		os.Exit(exitErrorCode)
	}
	if !x509.IsEncryptedPEMBlock(block) {
		color.Yellow("Key is not protected by a passphrase!")
		os.Exit(exitKeyNotProtectedCode)
	}
	fmt.Println("Key decoded and is protected by a passphrase.")
	if len(os.Args) == 4 && os.Args[3] == enableDerivationOptionName {
		fmt.Println("[+] Apply derivation operations on passphrases loaded...")
		var newPassphrases, errDerivation = derivatePassphraseCollection(passphrases)
		if errDerivation != nil {
			color.Red("Error during the derivation of the passphrases: %v", errDerivation.Error())
			os.Exit(exitErrorCode)
		}
		passphrases = newPassphrases
		fmt.Printf("%v passphrases loaded after the derivation.\n", len(passphrases))
	}
	fmt.Println("[+] Remove duplicates passphrases...")
	var finalPassphrases, errCleanup = removeDuplicatePassphrases(passphrases)
	if errCleanup != nil {
		color.Red("Error during the cleanup of the passphrases: %v", errCleanup.Error())
		os.Exit(exitErrorCode)
	}
	passphrases = finalPassphrases
	fmt.Printf("%v passphrases loaded after the derivation.\n", len(passphrases))
	fmt.Println("[+] Start brute force operations...")
	var valueToTest string
	comChannel := make(chan string, 1)
	var waitGroup sync.WaitGroup
	var start time.Time = time.Now()
	for _, passphrase := range passphrases {
		if len(comChannel) == 1 {
			//Passphrase was recovered
			break
		}
		valueToTest = strings.Trim(passphrase, "\n\r\t")
		fmt.Printf("\rTesting: %-50v", valueToTest)
		waitGroup.Add(1)
		go probePassphrase(valueToTest, block, comChannel, &waitGroup)
	}
	waitGroup.Wait()
	var delay time.Duration = time.Since(start)
	if len(comChannel) == 1 {
		var p string = <-comChannel
		color.Green("\rPassphrase recovered (%v): %-50v", delay, p)
	} else {
		color.Yellow("\rPassphrase not recovered (%v)!%-50v", delay, "")
	}
}

func derivatePassphraseCollection(passphrases []string) (updatedPassphrases []string, err error) {
	if len(passphrases) == 0 {
		return nil, errors.New("source list of passphrases cannot be empty")
	}
	//Map with derivation rules: KEY is the source character and VALUE is the replacement character
	var derivationRules = map[string]string{
		"0": "@",
		"l": "1",
	}
	//Apply derivations
	updatedPassphrases = make([]string, 0, (len(passphrases)*len(derivationRules))+(len(passphrases)*2))
	var updatedPassphrase string
	for _, passphrase := range passphrases {
		for key, value := range derivationRules {
			updatedPassphrases = append(updatedPassphrases, strings.ReplaceAll(passphrase, key, value))
		}
		updatedPassphrase = passphrase
		for key, value := range derivationRules {
			updatedPassphrase = strings.ReplaceAll(updatedPassphrase, key, value)
		}
		updatedPassphrases = append(updatedPassphrases, updatedPassphrase)
		updatedPassphrases = append(updatedPassphrases, passphrase)
	}
	return updatedPassphrases, nil

}

func removeDuplicatePassphrases(passphrases []string) (cleanedPassphrases []string, err error) {
	if len(passphrases) == 0 {
		return nil, errors.New("source list of passphrases cannot be empty")
	}
	//Use a map to achieve this because keys are not duplicated in such container
	var keys = make(map[string]int)
	for _, passphrase := range passphrases {
		keys[passphrase] = 1
	}
	cleanedPassphrases = make([]string, 0, len(keys))
	for key := range keys {
		cleanedPassphrases = append(cleanedPassphrases, key)
	}
	return cleanedPassphrases, nil
}

func probePassphrase(passphrase string, keyContent *pem.Block, comChannel chan string, waitGroup *sync.WaitGroup) {
	var privKeyBytes []byte
	var err error
	privKeyBytes, err = x509.DecryptPEMBlock(keyContent, []byte(passphrase))
	if err == nil {
		var validRSAHeader = regexp.MustCompile(`^RSA PRIVATE KEY$`)
		var validECHeader = regexp.MustCompile(`^EC(DSA)? PRIVATE KEY$`)
		switch {
		case validRSAHeader.MatchString(keyContent.Type):
			_, err := x509.ParsePKCS1PrivateKey(privKeyBytes)
			if err == nil {
				comChannel <- passphrase
			}
		case validECHeader.MatchString(keyContent.Type):
			_, err := x509.ParseECPrivateKey(privKeyBytes)
			if err == nil {
				comChannel <- passphrase
			}
		default:
			_, err := x509.ParsePKCS8PrivateKey(privKeyBytes)
			if err == nil {
				comChannel <- passphrase
			}
		}
	}
	waitGroup.Done()
}

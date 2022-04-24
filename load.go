package bootstrap

import (
	"encoding/json"
	"errors"
	"log"
	"os"

	"github.com/mervick/aes-everywhere/go/aes256"
)

// Service struct contains a slice of Accounts struct
type Service struct {
	Accounts []Accounts `json:"Accounts"`
}

// Accounts struct contains a Name value and Specs struct
type Accounts struct {
	Name  string `json:"Name"`
	Specs Specs  `json:"Specs"`
}

// Specs struct contains key values needed for that account.
type Specs struct {
	Domain   string `json:"Domain"`
	Password string `json:"Password"`
	Port     int64  `json:"Port"`
	Server   string `json:"Server"`
	Special  string `json:"Special"`
	Summary  string `json:"Summary"`
	User     string `json:"User"`
}

// HashEnv Struct for storing sensitive hashed password value in a JSON file
// instead of hardcoded
type HashEnv struct {
	BootHash string `json:"BootHash"`
}

// DecryptPasswords Method decrypts the Password for all accounts with a Password
// string in the Bootstrap_File (*Service) struct
func (s *Service) DecryptPasswords(h *HashEnv) {
	for i, _ := range s.Accounts {
		// Assume reasonable encrypted password length
		if len(s.Accounts[i].Specs.Password) > 8 {
			s.Accounts[i].Specs.Password = aes256.Decrypt(s.Accounts[i].Specs.Password, h.BootHash)
		}
	}

}

// GetAccount Method takes a string and searches for that string in Service Account records Name entity,
// then returns a single Accounts struct populated with queried Account.
func (s *Service) GetAccount(n string) (a Accounts) {
	for i, _ := range s.Accounts {
		// Assume reasonable encrypted password length
		if s.Accounts[i].Name == n {
			a.Name = s.Accounts[i].Name
			a.Specs = s.Accounts[i].Specs
			return a
		}
	}
	return a
}

// LoadFile Method loads the JSON Bootstrap_File passed as filename, then populates the struct
// Service via an Unmarshal
func (s *Service) LoadFile(filename string) error {
	_, err := os.Stat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return err
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Error reading: %s\n", filename)
		return err
	}
	err = json.Unmarshal(content, &s)
	if err != nil {
		log.Printf("Error unmarshaling: %s\n", filename)
		return err
	}
	return nil
}

// LoadFile Method loads the JSON Bootstrap_Hash passed as filename, then populates the struct
// HashEnv via an Unmarshal
func (s *HashEnv) LoadFile(filename string) error {
	_, err := os.Stat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return err
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Error reading: %s\n", filename)
		return err
	}
	err = json.Unmarshal(content, &s)
	if err != nil {
		log.Printf("Error unmarshaling: %s\n", filename)
		return err
	}
	return nil
}

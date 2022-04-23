package bootstrap

import (
	"encoding/json"
	"errors"
	"log"
	"os"

	"github.com/mervick/aes-everywhere/go/aes256"
)

// BootStrapEnv Struct for storing sensitive information in a JSON file
// instead of hardcoded
type BootStrapEnv struct {
	SqlDomain           string `json:"SqlDomain"`
	SqlUser             string `json:"SqlUser"`
	SqlPassword         string `json:"SqlPassword"`
	SQL_SERVER_FQDN     string `json:"SQL_SERVER_FQDN"`
	SQL_SERVER_DATABASE string `json:"SQL_SERVER_DATABASE"`
	SQL_SERVER_PORT     string `json:"SQL_SERVER_PORT"`
}

// HashEnv Struct for storing sensitive hashed password value in a JSON file
// instead of hardcoded
type HashEnv struct {
	StartHash string `json:"StartHash"`
}

// DecryptPassword Method decrypts the Sql Password and BindPassword stored in Bootstrap_File
func (s *BootStrapEnv) DecryptPassword(h *HashEnv) {
	s.SqlPassword = aes256.Decrypt(s.SqlPassword, h.StartHash)

}

// LoadFile Method loads the JSON Bootstrap_File passed as filename, then populates the struct
// BootStrapEnv via an Unmarshal
func (s *BootStrapEnv) LoadFile(filename string) error {
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

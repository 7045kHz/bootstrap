# bootstrap

Version: v0.0.8
Work In Progress - Expect changes

## What problem is this module trying to solve?

This package is an attempt to avoid having to include hardcoded passwords in code.
Instead, there is a default password stored in bootstrap_hash.json, which is used to encrypt user account passwords. Those encrypted passwords are then stored in bootstrap.json. So in your code, all you have to do is temporaraly decrypt the user password in a variable and include that variable in whatever code you need.

This is intended for server side deployments only, and assumes OS level security on the bootstrap_hash.json.

## About example bootstrap.json

The example bootstrap.json Password entry is encrypted against the BootHash value in bootstrap_hash.json. In this example, the value decrypts to a string password of "abc123".

### Example SQL connection string with a password defined in it

In the bootstrap.json there is an account named "ExampleSQL", the Accounts.Name = "ExampleSQL", the Accounts.Specs.Password is "U2FsdGVkX18qsa3BDnv7AOiIVtcxfTRb/Z2teuZt5JU="  when decrypted against the Boot hash password in bootstrap_hash.json the decrupted value of Accounts.Specs.Password is "abc123".

Now this value can be added to a Sql Connection string. In the example below, the SQL connection string in connString is build from the Port, Server, Password, User, Domain, and Special fields and results in a SQL Server connection string.


```go

package main

import (
	"database/sql"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/mervick/aes-everywhere/go/aes256"
	bs "github.com/7045kHz/bootstrap"
)

// Key bootstrap files, and default JSON header
const (
	Bootstrap_File      = "bootstrap.json"
	Bootstrap_Hash_File = "bootstrap_hash.json"
)

 

func main() {
	s1 := &bs.Service{}

    // load Bootstrap_File
	err := s1.LoadFile(Bootstrap_File)
	if err != nil {
		fmt.Println("Error openint test.json")
	}


	// Load Bootstrap_Hash_File
	h := bs.HashEnv{}
	h.LoadFile(Bootstrap_Hash_File)

    // get the account you want - in this case ExampleSQL - Accounts.Name = "ExampleSQL"
	sqlAccount := s1.GetAccount("ExampleSQL")
 
    // Print for debugging
	fmt.Printf("sqlAccount = %v\n", sqlAccount)
 
    // Create a connection string from the sqlAccount  which is the Accounts struct for "ExampleSQL"
	connString := fmt.Sprintf("server=%s;database=%s;user id=%s\\%s;password=%s;port=%d", sqlAccount.Specs.Server, sqlAccount.Specs.Special, sqlAccount.Specs.Domain, sqlAccount.Specs.User, sqlAccount.Specs.Password, sqlAccount.Specs.Port)

    // Printing for debugging
	fmt.Printf("Connect String: %v\n", connString)

    // Define a connection using the string
	db, err := sql.Open("mssql", connString)
	if err != nil {
		fmt.Printf("DB Open Error: %v\n", err)
	}
	defer db.Close()

    // Ping to establish the connection
	err = db.Ping()
	if err != nil {
		fmt.Printf("DB Ping Error: %v\n", err)
	}
}
 
 
 
```



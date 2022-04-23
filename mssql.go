package bootstrap

import (
	"database/sql"
	"fmt"

	_ "github.com/denisenkom/go-mssqldb"
)

func GetSpResults(db *sql.DB, whereClause string, v *StartupEnv) (*RetConnString, error) {
	var r RetConnString
	fmt.Printf("Incoming where: %v\n", whereClause)

	hashString := GetWhere(whereClause)
	fmt.Println(hashString)
	stmt, err := db.Prepare(hashString)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	err = stmt.QueryRow().Scan(&r.ApiKey, &r.DN, &r.Hash)
	if err != nil && err != sql.ErrNoRows {
		fmt.Printf("Errors in QueryRow.Scan: %v\n", err)
	}

	return &r, nil
}
func GetWhere(whereClause string) string {
	if whereClause != "" {

		return fmt.Sprintf(`EXEC sp_CheckApiKeyConditional "%s";`, whereClause)
	} else {

		return `EXEC sp_CheckApiKeyConditional`
	}
}

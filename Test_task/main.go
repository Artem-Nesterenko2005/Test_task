package main

import (
	"GO/database"
	"GO/server"
	"GO/tests"
	"fmt"
)

func main() {
	resultTests := tests.Tests()
	if resultTests != "" {
		fmt.Printf("Error tests:" + resultTests)
	}
	db := database.ConnectedDatabase()
	defer db.Db.Close()
	server.StartServer(db)
}

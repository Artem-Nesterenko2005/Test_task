package tests

import (
	"GO/database"
	"GO/tokens"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// Tests for tokens package
func testTokens() bool {
	_, err := tokens.GenerateUUID()
	if err != nil {
		return false
	}
	_, err = tokens.GenerateAccessToken("string")
	if err != nil {
		return false
	}
	_, err = tokens.GenerateRefreshToken("string")
	return err == nil
}

// Clear database after testDatabase
func clearTable(db database.DataBase) {
	_, err := db.Db.Exec("update test set refresh_hash = $1 where guid_id = $2", "null", uuid.Max)
	if err != nil {
		panic(err)
	}
	_, err = db.Db.Exec("update test set ip = $1 where guid_id = $2", "null", uuid.Max)
	if err != nil {
		panic(err)
	}
	_, err = db.Db.Exec("update test set uuid_access_token = $1 where guid_id = $2", "null", uuid.Max)
	if err != nil {
		panic(err)
	}
}

// Tests for database package
func testDatabase(db database.DataBase) bool {
	defer clearTable(db)
	db.AddRecord(uuid.Max, "123", "456", uuid.Max.String(), time.Now(), "test")
	result, err := db.GetGuidID("123", "test")
	if result != uuid.Max || err != nil {
		return false
	}

	result, err = db.GetUuidAccessToken(uuid.Max.String(), "test")
	if result.String() != uuid.Max.String() || err != nil {
		return false
	}

	resultIp := db.GetIpRefreshToken(uuid.Max.String(), "test")
	if resultIp != "456" {
		return false
	}

	_, err = db.SendEmail("000", "456", "test")
	return err == nil
}

// Check all test
func Tests() string {
	db := database.ConnectedDatabase()
	defer db.Db.Close()
	var result string

	if !testTokens() {
		result = "failed token tests"
	}
	if !testDatabase(db) {
		result += " failed database tests"
	}
	return result
}

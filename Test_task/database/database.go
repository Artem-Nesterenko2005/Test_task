package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// Structure for interactions with the database
type DataBase struct {
	Db *sql.DB
}

// Establishes a connection to the database
func ConnectedDatabase() DataBase {
	connStr := fmt.Sprintf("user=postgres password=%s dbname=user_info sslmode=disable", "8937367iii")
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	var dataBase DataBase = DataBase{Db: db}
	return dataBase
}

// Adds to the user by his guid_id data about the hash of the refresh token, the time of its creation, his IP
func (dbStruct *DataBase) AddRecord(guid_id uuid.UUID, newTokenHash string, ip string, uuidAccess string,
	timeCreate time.Time, tableName string) error {

	request := fmt.Sprintf("update %s set refresh_hash = $1 where guid_id = $2", tableName)
	_, err := dbStruct.Db.Exec(request, newTokenHash, guid_id)
	if err != nil {
		return err
	}
	request = fmt.Sprintf("update %s set ip = $1 where guid_id = $2", tableName)
	_, err = dbStruct.Db.Exec(request, ip, guid_id)
	if err != nil {
		return err
	}
	request = fmt.Sprintf("update %s set uuid_access_token = $1 where guid_id = $2", tableName)
	_, err = dbStruct.Db.Exec(request, uuidAccess, guid_id)
	if err != nil {
		return err
	}
	request = fmt.Sprintf("update %s set create_time = $1 where guid_id = $2", tableName)
	_, err = dbStruct.Db.Exec(request, timeCreate, guid_id)
	if err != nil {
		return err
	}
	return nil
}

// Gets the IP from the guid_id
func (dbStruct *DataBase) GetIpRefreshToken(guid_id string, tableName string) string {
	request := fmt.Sprintf("select ip from %s where guid_id = $1", tableName)
	result := dbStruct.Db.QueryRow(request, guid_id)
	var ip string
	err := result.Scan(&ip)
	if err != nil {
		return ""
	}
	return ip
}

// Gets the guid_id from the refresh token hash
func (dbStruct *DataBase) GetGuidID(refreshHash string, tableName string) (uuid.UUID, error) {
	request := fmt.Sprintf("select guid_id from %s where refresh_hash = $1", tableName)
	result := dbStruct.Db.QueryRow(request, refreshHash)
	var guid uuid.UUID
	err := result.Scan(&guid)
	if err != nil {
		return uuid.Nil, err
	}
	return guid, nil
}

// Gets the uuid access token from the guid_id
func (dbStruct *DataBase) GetUuidAccessToken(guid_id string, tableName string) (uuid.UUID, error) {
	request := fmt.Sprintf("select uuid_access_token from %s where guid_id = $1", tableName)
	result := dbStruct.Db.QueryRow(request, guid_id)
	var uuidAccessToken uuid.UUID
	err := result.Scan(&uuidAccessToken)
	if err != nil {
		return uuid.Nil, err
	}
	return uuidAccessToken, nil
}

// Sends a letter to the mail in case of change of the refresh token IP (mock data)
func (dbStruct *DataBase) SendEmail(userIp string, databaseIp string, tableName string) (string, error) {
	request := fmt.Sprintf("select refresh_hash from %s where ip = $1", tableName)
	result := dbStruct.Db.QueryRow(request, databaseIp)
	var ip string
	err := result.Scan(&ip)
	if err != nil {
		return "", err
	}
	message := fmt.Sprintf("Your token was used at address %s, old address %s", userIp, databaseIp)
	return message, nil
}

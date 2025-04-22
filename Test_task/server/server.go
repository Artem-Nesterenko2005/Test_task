package server

import (
	"GO/database"
	"GO/tokens"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Structure for sending data in JSON format
type TokensForRequest struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

// Structure for getting data from JSON format
type clientOldTokens struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	Guid_id      string `json:"guid_id"`
}

// Generates and returns a pair of tokens as JSON data
func addTokens(guid_id uuid.UUID, db database.DataBase, w http.ResponseWriter, r *http.Request) {
	userIp := r.Header.Get("X-FORWARDED-FOR")
	if userIp == "" {
		userIp = r.RemoteAddr
	}
	uuidAccessToken, err := tokens.GenerateUUID()
	if err != nil {
		http.Error(w, "Error while generating uuid Id", http.StatusInternalServerError)
		return
	}
	accessToken, err := tokens.GenerateAccessToken(uuidAccessToken)
	if err != nil {
		http.Error(w, "Error while generating access token", http.StatusInternalServerError)
		return
	}
	RefreshToken, err := tokens.GenerateRefreshToken(uuidAccessToken)
	if err != nil {
		http.Error(w, "Error while generating refresh token", http.StatusInternalServerError)
		return
	}
	RefreshToken.AccessToken = accessToken
	RefreshToken.UuidAccessToken = uuidAccessToken
	err = db.AddRecord(guid_id, RefreshToken.HashRefresh, userIp, RefreshToken.UuidAccessToken, RefreshToken.TimeCreate, "users")
	if err != nil {
		http.Error(w, "Error adding data to database", http.StatusInternalServerError)
		return
	}
	var requestTokens TokensForRequest = TokensForRequest{AccessToken: RefreshToken.AccessToken,
		RefreshToken: RefreshToken.Token}
	json, err := json.Marshal(requestTokens)
	if err != nil {
		http.Error(w, "Error trying to convert data to json", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(json)
	if err != nil {
		http.Error(w, "Error trying to write data", http.StatusInternalServerError)
		return
	}
}

// Returns a pair of tokens to the client
func GiveTokens(db database.DataBase, w http.ResponseWriter, r *http.Request) {
	guid_id, err := uuid.Parse(r.URL.Query().Get("guid_id"))
	if err != nil {
		http.Error(w, "Error reading guid_id client", http.StatusBadRequest)
		return
	}
	addTokens(guid_id, db, w, r)
}

// Refreshes a couple of tokens and issues new ones
func Refresh(db database.DataBase, w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading json data", http.StatusBadRequest)
		return
	}
	var req clientOldTokens
	err = json.Unmarshal(body, &req)
	if err != nil {
		http.Error(w, "Error converting data", http.StatusBadRequest)
		return
	}

	accessToken := req.AccessToken
	refreshToken := req.RefreshToken
	guid_id := req.Guid_id

	userIp := r.Header.Get("X-FORWARDED-FOR")
	if userIp == "" {
		userIp = r.RemoteAddr
	}
	databaseIp := db.GetIpRefreshToken(guid_id, "users")

	if databaseIp != userIp {
		message, err := db.SendEmail(userIp, databaseIp, "users")
		if err != nil {
			http.Error(w, "Error send message due to change ip", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, message)
	}
	databaseUuidAccess, err := db.GetUuidAccessToken(guid_id, "users")
	if err != nil {
		http.Error(w, "Error reading uuid access token from database", http.StatusInternalServerError)
		return
	}
	validation, err := tokens.CheckValidTokens(databaseUuidAccess, accessToken, refreshToken)
	if err != nil {
		http.Error(w, "Error while generating refresh token or access token", http.StatusInternalServerError)
		return
	}
	if !validation {
		http.Error(w, "Token validation error", http.StatusInternalServerError)
		return
	}
	uuidParse, err := uuid.Parse(guid_id)
	if err != nil {
		http.Error(w, "Error converting guid_id", http.StatusInternalServerError)
		return
	}
	addTokens(uuidParse, db, w, r)
}

// Starts the server, sets routes and their behavior
func StartServer(db database.DataBase) {
	router := mux.NewRouter()
	http.Handle("/", router)
	router.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		Refresh(db, w, r)
	})
	router.HandleFunc("/giveTokens", func(w http.ResponseWriter, r *http.Request) {
		GiveTokens(db, w, r)
	})
	http.ListenAndServe(":8888", nil)
}

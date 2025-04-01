package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// User represents a user in the banking system
type User struct {
	UserID     string
	Balance    float64
	UserSecret string // Secret key for HMAC (in production, store securely)
	LastNonce  string // Last used nonce in the chain
	NonceCount int    // Number of requests made (for desynchronization handling)
	mu         sync.Mutex
}

// BankServer manages the banking system
type BankServer struct {
	users map[string]*User // In production, use a database
	mu    sync.Mutex
}

// NewBankServer initializes a new bank server
func NewBankServer() *BankServer {
	return &BankServer{
		users: make(map[string]*User),
	}
}

// AddUser adds a new user to the bank
func (bs *BankServer) AddUser(userID, userSecret string, initialBalance float64) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	// Compute the first nonce: HMAC-SHA256(userID, userSecret)
	firstNonce := computeHMAC(userID, userSecret)

	bs.users[userID] = &User{
		UserID:     userID,
		Balance:    initialBalance,
		UserSecret: userSecret,
		LastNonce:  firstNonce,
		NonceCount: 0,
	}
}

// TransactionRequest represents a transaction request
type TransactionRequest struct {
	UserID    string  `json:"user_id"`
	Type      string  `json:"type"` // "withdraw" or "deposit"
	Amount    float64 `json:"amount"`
	Timestamp string  `json:"timestamp"` // ISO 8601 format
	Nonce     string  `json:"nonce"`     // Current nonce in the chain
	Signature string  `json:"signature"` // HMAC-SHA256(nonce|timestamp|type|amount, userSecret)
}

// Response represents the API response
type Response struct {
	Message   string  `json:"message,omitempty"`
	Balance   float64 `json:"balance,omitempty"`
	NextNonce string  `json:"next_nonce,omitempty"` // For client to use in the next request
	Error     string  `json:"error,omitempty"`
}

// computeHMAC computes an HMAC-SHA256 of the message using the key
func computeHMAC(message, key string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// computeNextNonce computes the next nonce in the chain
func computeNextNonce(previousNonce, userSecret string) string {
	return computeHMAC(previousNonce, userSecret)
}

// computeRequestSignature computes the signature for a transaction request
func computeRequestSignature(nonce, timestamp, txType string, amount float64, userSecret string) string {
	message := fmt.Sprintf("%s|%s|%s|%.2f", nonce, timestamp, txType, amount)
	return computeHMAC(message, userSecret)
}

// validateRequest validates a transaction request
func (bs *BankServer) validateRequest(req TransactionRequest) (*User, error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	// Check if the user exists
	fmt.Println(req)
	user, exists := bs.users[req.UserID]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	user.mu.Lock()
	defer user.mu.Unlock()

	// Validate the timestamp
	timestamp, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp format")
	}
	if time.Since(timestamp) > 5*time.Minute {
		return nil, fmt.Errorf("request timestamp too old")
	}

	// Compute the expected nonce
	expectedNonce := user.LastNonce
	for i := 0; i <= 2; i++ { // Allow a window of 3 nonces to handle desynchronization
		if expectedNonce == req.Nonce {
			// Update the last nonce to the next one in the chain
			for j := 0; j <= i; j++ {
				user.LastNonce = computeNextNonce(user.LastNonce, user.UserSecret)
				user.NonceCount++
			}
			break
		}
		if i == 2 {
			return nil, fmt.Errorf("invalid nonce: possible replay attack or desynchronization")
		}
		expectedNonce = computeNextNonce(expectedNonce, user.UserSecret)
	}

	// Validate the signature
	expectedSignature := computeRequestSignature(req.Nonce, req.Timestamp, req.Type, req.Amount, user.UserSecret)
	if req.Signature != expectedSignature {
		return nil, fmt.Errorf("invalid signature")
	}

	return user, nil
}

// transactionHandler handles withdraw and deposit requests
func transactionHandler(bs *BankServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		var req TransactionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}

		// Validate the request
		user, err := bs.validateRequest(req)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusBadRequest)
			return
		}

		// Process the transaction
		user.mu.Lock()
		defer user.mu.Unlock()

		switch strings.ToLower(req.Type) {
		case "withdraw":
			if req.Amount <= 0 {
				http.Error(w, `{"error":"amount must be positive"}`, http.StatusBadRequest)
				return
			}
			if user.Balance < req.Amount {
				http.Error(w, `{"error":"insufficient balance"}`, http.StatusBadRequest)
				return
			}
			user.Balance -= req.Amount
		case "deposit":
			if req.Amount <= 0 {
				http.Error(w, `{"error":"amount must be positive"}`, http.StatusBadRequest)
				return
			}
			user.Balance += req.Amount
		default:
			http.Error(w, `{"error":"invalid transaction type"}`, http.StatusBadRequest)
			return
		}

		// Compute the next nonce for the client
		nextNonce := computeNextNonce(req.Nonce, user.UserSecret)

		// Send the response
		resp := Response{
			Message:   fmt.Sprintf("%s successful", req.Type),
			Balance:   user.Balance,
			NextNonce: nextNonce,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}
}

func main() {
	// Initialize the bank server
	bs := NewBankServer()

	// Add a user (in production, this would come from a database)
	bs.AddUser("user123", "supersecret", 1000.0)

	// Set up the HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/transaction", transactionHandler(bs))

	// Start the server
	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

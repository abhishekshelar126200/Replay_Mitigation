package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// TransactionRequest represents a transaction request
type TransactionRequest struct {
	UserID    string  `json:"user_id"`
	Type      string  `json:"type"`
	Amount    float64 `json:"amount"`
	Timestamp string  `json:"timestamp"`
	Nonce     string  `json:"nonce"`
	Signature string  `json:"signature"`
}

// Response represents the API response
type Response struct {
	Message   string  `json:"message,omitempty"`
	Balance   float64 `json:"balance,omitempty"`
	NextNonce string  `json:"next_nonce,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// Client represents a banking client
type Client struct {
	UserID       string
	UserSecret   string
	CurrentNonce string
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

// NewClient initializes a new client
func NewClient(userID, userSecret string) *Client {
	// Compute the first nonce: HMAC-SHA256(userID, userSecret)
	firstNonce := computeHMAC(userID, userSecret)
	return &Client{
		UserID:       userID,
		UserSecret:   userSecret,
		CurrentNonce: firstNonce,
	}
}

// SendTransaction sends a transaction request to the server
func (c *Client) SendTransaction(txType string, amount float64) (Response, TransactionRequest, error) {
	// Prepare the request
	timestamp := time.Now().UTC().Format(time.RFC3339)
	signature := computeRequestSignature(c.CurrentNonce, timestamp, txType, amount, c.UserSecret)

	req := TransactionRequest{
		UserID:    c.UserID,
		Type:      txType,
		Amount:    amount,
		Timestamp: timestamp,
		Nonce:     c.CurrentNonce,
		Signature: signature,
	}

	// Convert the request to JSON
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return Response{}, TransactionRequest{}, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Send the request
	resp, err := http.Post("http://localhost:8080/transaction", "application/json", bytes.NewBuffer(reqBytes))
	if err != nil {
		return Response{}, TransactionRequest{}, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Parse the response
	var response Response
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return Response{}, TransactionRequest{}, fmt.Errorf("failed to decode response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return response, TransactionRequest{}, fmt.Errorf("transaction failed: %s", response.Error)
	}

	// Update the current nonce
	c.CurrentNonce = response.NextNonce

	return response, req, nil
}

// ReplayTransaction replays a previous transaction request
func (c *Client) ReplayTransaction(req TransactionRequest) (Response, error) {
	// Convert the request to JSON
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Send the request
	resp, err := http.Post("http://localhost:8080/transaction", "application/json", bytes.NewBuffer(reqBytes))
	if err != nil {
		return Response{}, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Parse the response
	var response Response
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return Response{}, fmt.Errorf("failed to decode response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return response, fmt.Errorf("transaction failed: %s", response.Error)
	}

	return response, nil
}

func main() {
	// Initialize the client
	client := NewClient("user123", "supersecret")

	// Perform a deposit
	resp, _, err := client.SendTransaction("deposit", 500.0)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Deposit successful: %s, New Balance: %.2f\n", resp.Message, resp.Balance)
	}

	// Perform a withdrawal
	resp, withdrawReq, err := client.SendTransaction("withdraw", 200.0)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Withdrawal successful: %s, New Balance: %.2f\n", resp.Message, resp.Balance)
	}

	// Try to replay the last withdrawal request (should fail)
	resp, err = client.ReplayTransaction(withdrawReq)
	if err != nil {
		fmt.Println("Error (expected due to replay):", err)
	} else {
		fmt.Printf("Replay successful (unexpected): %s, New Balance: %.2f\n", resp.Message, resp.Balance)
	}
}

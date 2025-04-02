# Banking System Replay Attack Mitigation

This project implements a secure banking system API that mitigates replay attacks using a nonce chain, timestamps, and request signatures. Below is the explanation of the approach, detailing how the client and server interact to ensure the authenticity and uniqueness of each transaction request.

## Explanation

This plan implements a replay attack mitigation strategy for a banking system API by using a nonce chain, timestamps, and request signatures to ensure the authenticity and uniqueness of each transaction request.

1. **Share a Secret Code**: The client and server share a `userSecret` (a cryptographic key) during user registration, stored securely on both sides for HMAC operations.
2. **Start with a Nonce**: The first nonce is computed as `nonce_0 = HMAC-SHA256(userID, userSecret)`, establishing the start of a deterministic nonce chain.
3. **Make a Request**: For a transaction (e.g., deposit $500), the client sends a `POST /transaction` request with the `userID`, transaction type, amount, a timestamp (ISO 8601 format), the current nonce, and a signature: `HMAC-SHA256(nonce|timestamp|type|amount, userSecret)`.
4. **Bank Checks the Time**: The server validates the timestamp, ensuring it’s within a 5-minute window (`time.Since(timestamp) <= 5 minutes`) to prevent old requests from being accepted.
5. **Bank Checks the Nonce**: The server computes the expected nonce (starting from `nonce_0` and iterating with `HMAC-SHA256(previousNonce, userSecret)`) and verifies it matches the client’s nonce, ensuring the request hasn’t been replayed.
6. **Bank Checks the Signature**: The server recomputes the signature using the same inputs and `userSecret`, verifying it matches the client’s signature to confirm the request’s integrity and authenticity.
7. **Process the Transaction**: If all validations pass, the server processes the transaction (e.g., updates the user’s balance by adding $500) and persists the updated state.
8. **Get the Next Nonce**: The server computes the next nonce (`nextNonce = HMAC-SHA256(currentNonce, userSecret)`), updates its `LastNonce`, and includes the `nextNonce` in the response (`200 OK` with `{message, balance, next_nonce}`).
9. **Stop Replays**: A replayed request fails because the nonce will no longer match the server’s expected nonce (since `LastNonce` has advanced) or the timestamp will be outside the 5-minute window, resulting in a `400 Bad Request` response.
10. **Handle Mistakes**: The server allows a small window of nonces (e.g., up to 3 ahead) to handle desynchronization; if the client and server diverge too far, the client must re-authenticate to reset the nonce chain to `nonce_0`.

## Usage

To run the banking system:
1. Clone the repository into your local pc `git clone https://github.com/abhishekshelar126200/Replay_Mitigation`
1. Navigate to the server directory `cd server`
2. Start the server: `go run main.go`
3. Navigate to the server directory `cd client`
4. Run the client to perform transactions: `go run main.go`

The client will send transaction requests (e.g., deposits and withdrawals), and the server will validate them to prevent replay attacks.

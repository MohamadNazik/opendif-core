package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// AsyncRequest represents a record in async_requests table
type AsyncRequest struct {
	TransactionID   string          `json:"transaction_id"`
	ClientID        string          `json:"client_id"`
	Status          string          `json:"status"`
	OriginalQuery   string          `json:"original_query"`
	CombinedPayload json.RawMessage `json:"combined_payload,omitempty"`
	ErrorMessage    sql.NullString  `json:"error_message,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// AsyncProviderResponse represents a record in async_provider_responses table
type AsyncProviderResponse struct {
	ID            int             `json:"id"`
	TransactionID string          `json:"transaction_id"`
	ProviderKey   string          `json:"provider_key"`
	SchemaID      string          `json:"schema_id"`
	Status        string          `json:"status"`
	Payload       json.RawMessage `json:"payload,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// createAsyncTables creates the tables needed for async requests
func (s *SchemaDB) createAsyncTables() error {
	createRequestsTable := `
	CREATE TABLE IF NOT EXISTS async_requests (
		transaction_id VARCHAR(36) PRIMARY KEY,
		client_id VARCHAR(100) NOT NULL,
		status VARCHAR(20) NOT NULL DEFAULT 'pending',
		original_query TEXT NOT NULL,
		combined_payload JSONB,
		error_message TEXT,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);`

	if _, err := s.db.Exec(createRequestsTable); err != nil {
		return fmt.Errorf("failed to create async_requests table: %w", err)
	}

	createProviderResponsesTable := `
	CREATE TABLE IF NOT EXISTS async_provider_responses (
		id SERIAL PRIMARY KEY,
		transaction_id VARCHAR(36) REFERENCES async_requests(transaction_id) ON DELETE CASCADE,
		provider_key VARCHAR(50) NOT NULL,
		schema_id VARCHAR(100) NOT NULL,
		status VARCHAR(20) NOT NULL DEFAULT 'pending',
		payload JSONB,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		UNIQUE(transaction_id, provider_key)
	);`

	if _, err := s.db.Exec(createProviderResponsesTable); err != nil {
		return fmt.Errorf("failed to create async_provider_responses table: %w", err)
	}

	return nil
}

// CreateAsyncRequest inserts a new async request record
func (s *SchemaDB) CreateAsyncRequest(txID, clientID, originalQuery string) error {
	query := `
		INSERT INTO async_requests (transaction_id, client_id, status, original_query)
		VALUES ($1, $2, 'pending', $3)`

	_, err := s.db.Exec(query, txID, clientID, originalQuery)
	if err != nil {
		return fmt.Errorf("failed to create async request: %w", err)
	}
	return nil
}

// CreateProviderResponse inserts a pending response record for a provider
func (s *SchemaDB) CreateProviderResponse(txID, providerKey, schemaID string) error {
	query := `
		INSERT INTO async_provider_responses (transaction_id, provider_key, schema_id, status)
		VALUES ($1, $2, $3, 'pending')
		ON CONFLICT (transaction_id, provider_key) DO UPDATE
		SET status = 'pending', payload = NULL, updated_at = NOW()`

	_, err := s.db.Exec(query, txID, providerKey, schemaID)
	if err != nil {
		return fmt.Errorf("failed to create provider response: %w", err)
	}
	return nil
}

// UpdateProviderResponse updates the status and payload of a provider response
func (s *SchemaDB) UpdateProviderResponse(txID, providerKey string, payload []byte) error {
	query := `
		UPDATE async_provider_responses
		SET status = 'completed', payload = $1, updated_at = NOW()
		WHERE transaction_id = $2 AND provider_key = $3`

	_, err := s.db.Exec(query, payload, txID, providerKey)
	if err != nil {
		return fmt.Errorf("failed to update provider response: %w", err)
	}
	return nil
}

// FailProviderResponse marks a single provider's response as failed, recording the error.
// The error is stored in the payload column as a JSON error object so it can be
// surfaced when the overall request is later reported as failed.
func (s *SchemaDB) FailProviderResponse(txID, providerKey, errMsg string) error {
	errPayload, marshalErr := json.Marshal(map[string]string{"error": errMsg})
	if marshalErr != nil {
		errPayload = []byte(`{"error":"unknown error"}`)
	}

	query := `
		UPDATE async_provider_responses
		SET status = 'failed', payload = $1, updated_at = NOW()
		WHERE transaction_id = $2 AND provider_key = $3`

	_, err := s.db.Exec(query, errPayload, txID, providerKey)
	if err != nil {
		return fmt.Errorf("failed to mark provider response as failed: %w", err)
	}
	return nil
}

// GetProviderResponseStatusCounts returns the number of provider responses for a
// transaction that are still pending and the number that have failed.
func (s *SchemaDB) GetProviderResponseStatusCounts(txID string) (pending int, failed int, err error) {
	query := `
		SELECT
			COUNT(*) FILTER (WHERE status = 'pending') AS pending,
			COUNT(*) FILTER (WHERE status = 'failed') AS failed
		FROM async_provider_responses
		WHERE transaction_id = $1`

	err = s.db.QueryRow(query, txID).Scan(&pending, &failed)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get provider response status counts: %w", err)
	}
	return pending, failed, nil
}

// GetAllProviderResponses retrieves all completed responses for a transaction
func (s *SchemaDB) GetAllProviderResponses(txID string) ([]AsyncProviderResponse, error) {
	query := `
		SELECT id, transaction_id, provider_key, schema_id, status, payload, created_at, updated_at
		FROM async_provider_responses
		WHERE transaction_id = $1`

	rows, err := s.db.Query(query, txID)
	if err != nil {
		return nil, fmt.Errorf("failed to query provider responses: %w", err)
	}
	defer rows.Close()

	var responses []AsyncProviderResponse
	for rows.Next() {
		var resp AsyncProviderResponse
		var payload []byte
		err := rows.Scan(&resp.ID, &resp.TransactionID, &resp.ProviderKey, &resp.SchemaID, &resp.Status, &payload, &resp.CreatedAt, &resp.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan provider response: %w", err)
		}
		resp.Payload = json.RawMessage(payload)
		responses = append(responses, resp)
	}
	return responses, nil
}

// CompleteAsyncRequest updates the main async request status to completed and sets the
// aggregated payload, but only if the request is still 'pending'. It returns applied=true
// if this call actually performed the transition, and false if the request had already been
// finalized (completed or failed) by another goroutine - callers should treat false as a
// no-op rather than an error.
func (s *SchemaDB) CompleteAsyncRequest(txID string, combinedPayload []byte) (applied bool, err error) {
	query := `
		UPDATE async_requests
		SET status = 'completed', combined_payload = $1, updated_at = NOW()
		WHERE transaction_id = $2 AND status = 'pending'`

	result, err := s.db.Exec(query, combinedPayload, txID)
	if err != nil {
		return false, fmt.Errorf("failed to complete async request: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to determine rows affected completing async request: %w", err)
	}
	return rowsAffected > 0, nil
}

// FailAsyncRequest updates the main async request status to failed and sets the error
// message, but only if the request is still 'pending'. It returns applied=true if this call
// actually performed the transition, and false if the request had already been finalized by
// another goroutine.
func (s *SchemaDB) FailAsyncRequest(txID string, errMsg string) (applied bool, err error) {
	query := `
		UPDATE async_requests
		SET status = 'failed', error_message = $1, updated_at = NOW()
		WHERE transaction_id = $2 AND status = 'pending'`

	result, err := s.db.Exec(query, errMsg, txID)
	if err != nil {
		return false, fmt.Errorf("failed to fail async request: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to determine rows affected failing async request: %w", err)
	}
	return rowsAffected > 0, nil
}

// GetAsyncRequest retrieves an async request by its transaction ID
func (s *SchemaDB) GetAsyncRequest(txID string) (*AsyncRequest, error) {
	query := `
		SELECT transaction_id, client_id, status, original_query, combined_payload, error_message, created_at, updated_at
		FROM async_requests
		WHERE transaction_id = $1`

	row := s.db.QueryRow(query, txID)
	req := &AsyncRequest{}
	var combinedPayload []byte
	err := row.Scan(&req.TransactionID, &req.ClientID, &req.Status, &req.OriginalQuery, &combinedPayload, &req.ErrorMessage, &req.CreatedAt, &req.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("transaction %s not found", txID)
		}
		return nil, fmt.Errorf("failed to get async request: %w", err)
	}
	req.CombinedPayload = json.RawMessage(combinedPayload)
	return req, nil
}

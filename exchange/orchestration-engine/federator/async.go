package federator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/OpenDIF/opendif-core/exchange/shared/monitoring"
	"github.com/ginaxu1/gov-dx-sandbox/exchange/orchestration-engine/auth"
	"github.com/ginaxu1/gov-dx-sandbox/exchange/orchestration-engine/consent"
	"github.com/ginaxu1/gov-dx-sandbox/exchange/orchestration-engine/database"
	"github.com/ginaxu1/gov-dx-sandbox/exchange/orchestration-engine/internals/errors"
	"github.com/ginaxu1/gov-dx-sandbox/exchange/orchestration-engine/logger"
	auth2 "github.com/ginaxu1/gov-dx-sandbox/exchange/orchestration-engine/pkg/auth"
	"github.com/ginaxu1/gov-dx-sandbox/exchange/orchestration-engine/pkg/graphql"
	"github.com/ginaxu1/gov-dx-sandbox/exchange/orchestration-engine/policy"
	"github.com/ginaxu1/gov-dx-sandbox/exchange/orchestration-engine/provider"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"
)

// SubmitAsyncQuery handles POST /public/graphql/async
func (f *Federator) SubmitAsyncQuery(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req graphql.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Log.Error("Failed to decode request body", "error", err)
		http.Error(w, "Bad request: invalid JSON", http.StatusBadRequest)
		return
	}

	// Decode the token using the cached TokenValidator
	consumerAssertion, err := auth.GetConsumerJwtFromTokenWithValidator(&f.Configs.JWT, f.Configs.TrustUpstream, r, f.TokenValidator)
	if err != nil {
		logger.Log.Error("Failed to get consumer JWT from token", "error", err)
		http.Error(w, "Unauthorized: invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Process validation, PDP check, and Consent check
	src := source.NewSource(&source.Source{
		Body: []byte(req.Query),
		Name: "Query",
	})

	doc, err := parser.Parse(parser.ParseParams{Source: src})
	if err != nil {
		logger.Log.Error("Failed to parse query", "Error", err)
		http.Error(w, "Bad request: invalid GraphQL query", http.StatusBadRequest)
		return
	}

	// Get active schema
	var schema *ast.Document
	if f.SchemaService != nil {
		schema, _ = f.getActiveSchemaFromService()
	}
	if schema == nil && f.Configs.Schema != nil {
		schema, _ = f.Configs.GetSchemaDocument()
	}
	if schema == nil {
		schema, err = f.loadSchemaFromFile()
		if err != nil {
			logger.Log.Error("Failed to load schema", "Error", err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(createErrorResponseWithCode("No active schema found", errors.CodePDPError))
			return
		}
	}

	// Collect directives
	schemaCollection, err := ProviderSchemaCollector(schema, doc)
	if err != nil {
		logger.Log.Error("Failed to collect provider schema", "Error", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(graphql.Response{
			Errors: []interface{}{err.(*graphql.JSONError)},
		})
		return
	}

	// Get arguments
	var argMapping []*graphql.ArgMapping
	if f.Configs.ArgMapping != nil {
		argMapping = f.Configs.ArgMapping
	}
	requiredArguments := FindRequiredArguments(schemaCollection.ProviderFieldMap, argMapping)
	extractedArgs := ExtractRequiredArguments(requiredArguments, schemaCollection.Arguments)
	if req.Variables != nil {
		PushVariablesFromVariableDefinition(req, extractedArgs, schemaCollection.VariableDefinitions)
	}

	// Initialize PDP and CE clients
	var pdpClient *policy.PdpClient
	var ceClient *consent.CEServiceClient
	if f.Configs.PdpConfig.ClientURL != "" {
		pdpClient = policy.NewPdpClient(f.Configs.PdpConfig.ClientURL)
	}
	if f.Configs.CeConfig.ClientURL != "" {
		ceClient = consent.NewCEServiceClient(f.Configs.CeConfig.ClientURL)
	}

	// PDP Decide
	var pdpResponse *policy.PdpResponse
	if pdpClient != nil {
		pdpRequest := &policy.PdpRequest{
			AppId: consumerAssertion.ApplicationID,
		}
		requiredFields := make([]policy.RequiredField, 0)
		for _, field := range *schemaCollection.ProviderFieldMap {
			requiredFields = append(requiredFields, policy.RequiredField{
				SchemaID:  field.SchemaId,
				FieldName: field.FieldPath,
			})
		}
		pdpRequest.RequiredFields = requiredFields

		pdpResponse, err = pdpClient.MakePdpRequest(r.Context(), pdpRequest)
		if err != nil {
			logger.Log.Error("PDP request failed", "error", err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(createErrorResponseWithCode("Authorization check failed", errors.CodePDPError))
			return
		}
		if pdpResponse == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(createErrorResponseWithCode("No response from PDP", errors.CodePDPNoResponse))
			return
		}

		if !pdpResponse.AppAuthorized {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(createErrorResponse("Access denied", map[string]interface{}{
				"code":               errors.CodePDPNotAllowed,
				"unauthorizedFields": pdpResponse.UnauthorizedFields,
			}))
			return
		}
		if pdpResponse.AppAccessExpired {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(createErrorResponse("Access expired", map[string]interface{}{
				"code":          errors.CodePDPNotAllowed,
				"expiredFields": pdpResponse.ExpiredFields,
			}))
			return
		}
	}

	// Extract citizen ID
	var dataOwnerID string
	if len(extractedArgs) > 0 {
		val := extractedArgs[0].Value.GetValue()
		if s, ok := val.(string); ok {
			dataOwnerID = s
		}
	}
	if dataOwnerID == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(createErrorResponseWithCode("Data Owner ID argument is missing or invalid", errors.CodeMissingEntityIdentifier))
		return
	}

	// Consent Check
	if pdpResponse != nil && pdpResponse.AppRequiresOwnerConsent {
		if ceClient == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(createErrorResponseWithCode("Consent required but Consent Engine not available", errors.CodeCEError))
			return
		}
		fields := make([]consent.ConsentField, len(pdpResponse.ConsentRequiredFields))
		for i, f := range pdpResponse.ConsentRequiredFields {
			fields[i].FieldName = f.FieldName
			fields[i].SchemaID = f.SchemaID
			fields[i].DisplayName = f.DisplayName
			fields[i].Description = f.Description
			if f.Owner != nil {
				fields[i].Owner = consent.OwnerType(*f.Owner)
			} else {
				fields[i].Owner = consent.OwnerCitizen
			}
		}

		typeRealTime := consent.TypeRealtime
		ceRequest := &consent.CreateConsentRequest{
			AppID: consumerAssertion.ApplicationID,
			ConsentRequirement: consent.ConsentRequirement{
				Owner:      consent.OwnerCitizen,
				OwnerID:    dataOwnerID,
				OwnerEmail: dataOwnerID,
				Fields:     fields,
			},
			ConsentType: &typeRealTime,
		}

		ceResp, err := ceClient.CreateConsent(r.Context(), ceRequest)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(createErrorResponseWithCode("Consent Engine request failed", errors.CodeCEError))
			return
		}
		if ceResp == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(createErrorResponseWithCode("No response from Consent Engine", errors.CodeCENoResponse))
			return
		}

		if ceResp.Status != consent.StatusApproved {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(createErrorResponse("Consent not approved", map[string]interface{}{
				"code":             errors.CodeCENotApproved,
				"consentPortalUrl": ceResp.ConsentPortalURL,
				"consentStatus":    ceResp.Status,
			}))
			return
		}
	}

	// Build provider sub-queries
	splitRequests, err := QueryBuilder(schemaCollection.ProviderFieldMap, extractedArgs)
	if err != nil {
		logger.Log.Error("Failed to build queries", "Error", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(graphql.Response{
			Errors: []interface{}{err.(*graphql.JSONError)},
		})
		return
	}
	if len(splitRequests) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(createErrorResponse("No valid service queries found in the request", nil))
		return
	}

	// Initialize Async Request in database
	if f.Db == nil {
		logger.Log.Error("Database not initialized for async queries")
		http.Error(w, "Internal server error: database not available", http.StatusInternalServerError)
		return
	}

	txID := uuid.New().String()
	err = f.Db.CreateAsyncRequest(txID, consumerAssertion.ApplicationID, req.Query)
	if err != nil {
		logger.Log.Error("Failed to create async request in DB", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// First pass: resolve every provider and insert its (pending) response row.
	// This must complete for ALL providers before any background fetch is started,
	// otherwise a fast provider could finish and see an incomplete row set, making
	// GetProviderResponseStatusCounts() report "nothing pending" prematurely.
	type resolvedProvider struct {
		splitReq *federationServiceRequest
		provider *provider.Provider
	}
	resolved := make([]resolvedProvider, 0, len(splitRequests))
	for _, splitReq := range splitRequests {
		p, exists := f.ProviderHandler.GetProvider(splitReq.ServiceKey, splitReq.SchemaID)
		if !exists {
			logger.Log.Warn("Provider not found for async request", "providerKey", splitReq.ServiceKey)
			if _, failErr := f.Db.FailAsyncRequest(txID, fmt.Sprintf("provider %s not found", splitReq.ServiceKey)); failErr != nil {
				logger.Log.Error("Failed to mark async request as failed", "error", failErr)
			}
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if err = f.Db.CreateProviderResponse(txID, splitReq.ServiceKey, splitReq.SchemaID); err != nil {
			logger.Log.Error("Failed to create provider response in DB", "error", err)
			if _, failErr := f.Db.FailAsyncRequest(txID, err.Error()); failErr != nil {
				logger.Log.Error("Failed to mark async request as failed", "error", failErr)
			}
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		resolved = append(resolved, resolvedProvider{splitReq: splitReq, provider: p})
	}

	// Second pass: now that every provider row exists, it's safe to start the
	// background fetches - none of them can observe an incomplete row set.
	traceID := monitoring.GetTraceIDFromContext(r.Context())
	for _, rp := range resolved {
		// Run background fetch using context.Background() so it outlives the client request
		bgCtx := context.Background()
		if traceID != "" {
			bgCtx = monitoring.WithTraceID(bgCtx, traceID)
		}
		go f.fetchProviderAsync(bgCtx, txID, rp.splitReq, rp.provider)
	}

	// Respond with 202 Accepted
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"transactionId": txID,
		"status":        "pending",
	})
}

// getActiveSchemaFromService calls GetActiveSchema method on SchemaService using reflection
func (f *Federator) getActiveSchemaFromService() (*ast.Document, error) {
	if f.SchemaService == nil {
		return nil, nil
	}
	schemaServiceValue := reflect.ValueOf(f.SchemaService)
	if !schemaServiceValue.IsValid() || schemaServiceValue.IsNil() {
		return nil, nil
	}
	getActiveSchemaMethod := schemaServiceValue.MethodByName("GetActiveSchema")
	if !getActiveSchemaMethod.IsValid() {
		return nil, nil
	}
	results := getActiveSchemaMethod.Call([]reflect.Value{})
	if len(results) >= 2 && !results[1].IsNil() {
		return nil, results[1].Interface().(error)
	}
	if len(results) >= 1 && !results[0].IsNil() {
		schemaRecord := results[0].Interface()
		schemaRecordValue := reflect.ValueOf(schemaRecord)
		if schemaRecordValue.Kind() == reflect.Ptr {
			schemaRecordValue = schemaRecordValue.Elem()
		}
		sdlField := schemaRecordValue.FieldByName("SDL")
		if sdlField.IsValid() && sdlField.Kind() == reflect.String {
			sdlString := sdlField.String()
			src := source.NewSource(&source.Source{
				Body: []byte(sdlString),
				Name: "ActiveSchema",
			})
			return parser.Parse(parser.ParseParams{Source: src})
		}
	}
	return nil, nil
}

// asyncCallbackFallbackBaseURL is only used when no public base URL is configured
// (e.g. local development), so the async flow still works out of the box.
const asyncCallbackFallbackBaseURL = "http://localhost:4000"

// fetchProviderAsync executes query request to provider in background
func (f *Federator) fetchProviderAsync(ctx context.Context, txID string, req *federationServiceRequest, prov *provider.Provider) {
	reqBody, err := json.Marshal(req.GraphQLRequest)
	if err != nil {
		logger.Log.Error("Failed to marshal request for provider", "provider", req.ServiceKey, "error", err)
		f.failProviderResponseAndCheckCompletion(txID, req.ServiceKey, fmt.Sprintf("failed to marshal provider request: %v", err))
		return
	}

	// Construct callback URL using the configured public base URL for this OE instance
	// so providers running outside this machine (staging/prod) can reach it.
	callbackBaseURL := f.Configs.Server.PublicBaseURL
	if callbackBaseURL == "" {
		logger.Log.Warn("Server.PublicBaseURL is not configured; falling back to localhost callback URL, which will not be reachable outside local development", "provider", req.ServiceKey)
		callbackBaseURL = asyncCallbackFallbackBaseURL
	}
	callbackURL := fmt.Sprintf("%s/api/v1/callback?transactionId=%s&providerKey=%s", strings.TrimSuffix(callbackBaseURL, "/"), txID, req.ServiceKey)

	providerURL := prov.ServiceUrl
	if strings.Contains(providerURL, "?") {
		providerURL += "&callback=" + url.QueryEscape(callbackURL)
	} else {
		providerURL += "?callback=" + url.QueryEscape(callbackURL)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", providerURL, bytes.NewBuffer(reqBody))
	if err != nil {
		logger.Log.Error("Failed to create provider request", "provider", req.ServiceKey, "error", err)
		f.failProviderResponseAndCheckCompletion(txID, req.ServiceKey, fmt.Sprintf("failed to create provider request: %v", err))
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Callback-URL", callbackURL)

	// Propagate traceID
	traceID := monitoring.GetTraceIDFromContext(ctx)
	if traceID != "" {
		httpReq.Header.Set("X-Trace-ID", traceID)
	}

	var resp *http.Response
	if prov.Auth != nil {
		switch prov.Auth.Type {
		case auth2.AuthTypeOAuth2:
			if prov.OAuth2Config != nil {
				client := prov.OAuth2Config.Client(ctx)
				resp, err = client.Do(httpReq)
			} else {
				resp, err = f.Client.Do(httpReq)
			}
		case auth2.AuthTypeAPIKey:
			httpReq.Header.Set(prov.Auth.APIKeyName, prov.Auth.APIKeyValue)
			resp, err = f.Client.Do(httpReq)
		default:
			resp, err = f.Client.Do(httpReq)
		}
	} else {
		resp, err = f.Client.Do(httpReq)
	}

	if err != nil {
		logger.Log.Error("Async request failed to provider", "provider", req.ServiceKey, "error", err)
		f.failProviderResponseAndCheckCompletion(txID, req.ServiceKey, fmt.Sprintf("request to provider failed: %v", err))
		return
	}
	defer resp.Body.Close()

	// A non-2xx status means the provider rejected or failed the request outright - it will
	// never call back for this transaction, so fail this provider's response now instead of
	// leaving it pending forever.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		logger.Log.Error("Provider returned non-success status for async request", "provider", req.ServiceKey, "status", resp.StatusCode, "body", string(body))
		f.failProviderResponseAndCheckCompletion(txID, req.ServiceKey, fmt.Sprintf("provider returned status %d", resp.StatusCode))
		return
	}

	// If provider returns 200 OK, parse the body to check if it returned the data payload synchronously.
	// This fallback ensures compatibility with synchronous mock providers out of the box.
	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.Log.Error("Failed to read response body from provider", "provider", req.ServiceKey, "error", err)
			f.failProviderResponseAndCheckCompletion(txID, req.ServiceKey, fmt.Sprintf("failed to read provider response body: %v", err))
			return
		}

		var check map[string]interface{}
		if err := json.Unmarshal(body, &check); err == nil {
			if _, hasData := check["data"]; hasData {
				logger.Log.Info("Received synchronous response from provider in async query, processing directly", "provider", req.ServiceKey)
				f.updateProviderResponseAndCheckCompletion(txID, req.ServiceKey, body)
				return
			}
			if _, hasErrors := check["errors"]; hasErrors {
				logger.Log.Error("Provider returned a synchronous error response for async request", "provider", req.ServiceKey)
				f.failProviderResponseAndCheckCompletion(txID, req.ServiceKey, "provider returned a synchronous error response")
				return
			}
		}
		// Body has neither "data" nor "errors" (e.g. a bare acknowledgement) - the provider is
		// expected to deliver the real result later via the callback URL.
	}
}

// updateProviderResponseAndCheckCompletion stores provider payload and triggers aggregation if complete
func (f *Federator) updateProviderResponseAndCheckCompletion(txID, providerKey string, payload []byte) {
	if f.Db == nil {
		logger.Log.Error("Database not available to save provider response")
		return
	}

	err := f.Db.UpdateProviderResponse(txID, providerKey, payload)
	if err != nil {
		logger.Log.Error("Failed to update provider response in DB", "transactionId", txID, "providerKey", providerKey, "error", err)
		return
	}

	f.checkTransactionCompletion(txID)
}

// failProviderResponseAndCheckCompletion marks a single provider's response as failed and,
// once no provider responses remain pending, finalizes the overall transaction as failed so
// clients polling for status don't wait forever on a provider that will never call back.
func (f *Federator) failProviderResponseAndCheckCompletion(txID, providerKey, errMsg string) {
	if f.Db == nil {
		logger.Log.Error("Database not available to save provider response failure")
		return
	}

	if err := f.Db.FailProviderResponse(txID, providerKey, errMsg); err != nil {
		logger.Log.Error("Failed to mark provider response as failed in DB", "transactionId", txID, "providerKey", providerKey, "error", err)
		return
	}

	f.checkTransactionCompletion(txID)
}

// checkTransactionCompletion checks whether every provider response for a transaction has
// resolved (completed or failed) and, if so, finalizes the transaction: as failed if any
// provider failed, otherwise by aggregating all provider payloads.
func (f *Federator) checkTransactionCompletion(txID string) {
	pending, failed, err := f.Db.GetProviderResponseStatusCounts(txID)
	if err != nil {
		logger.Log.Error("Failed to get provider response status counts", "transactionId", txID, "error", err)
		return
	}

	if pending > 0 {
		return
	}

	if failed > 0 {
		logger.Log.Warn("One or more providers failed for transaction, failing request", "transactionId", txID, "failedProviders", failed)
		if _, err := f.Db.FailAsyncRequest(txID, fmt.Sprintf("%d provider(s) failed to respond", failed)); err != nil {
			logger.Log.Error("Failed to mark async request as failed", "transactionId", txID, "error", err)
		}
		return
	}

	logger.Log.Info("All providers completed for transaction. Merging payloads...", "transactionId", txID)
	f.aggregateAndCompleteRequest(txID)
}

// aggregateAndCompleteRequest loads all provider payloads, runs federation accumulator, and writes results to DB
func (f *Federator) aggregateAndCompleteRequest(txID string) {
	var asyncReq *database.AsyncRequest
	asyncReq, err := f.Db.GetAsyncRequest(txID)
	if err != nil {
		logger.Log.Error("Failed to get async request from DB", "transactionId", txID, "error", err)
		return
	}

	src := source.NewSource(&source.Source{
		Body: []byte(asyncReq.OriginalQuery),
		Name: "Query",
	})
	doc, err := parser.Parse(parser.ParseParams{Source: src})
	if err != nil {
		logger.Log.Error("Failed to parse original query", "transactionId", txID, "error", err)
		f.failAsyncRequest(txID, fmt.Sprintf("failed to parse original query: %v", err))
		return
	}

	var schema *ast.Document
	if f.SchemaService != nil {
		schema, _ = f.getActiveSchemaFromService()
	}
	if schema == nil && f.Configs.Schema != nil {
		schema, _ = f.Configs.GetSchemaDocument()
	}
	if schema == nil {
		schema, err = f.loadSchemaFromFile()
		if err != nil {
			logger.Log.Error("Failed to load schema", "transactionId", txID, "error", err)
			f.failAsyncRequest(txID, "active schema not found")
			return
		}
	}

	// Build Schema Info Map for merging
	schemaInfoMap, err := BuildSchemaInfoMap(schema, doc)
	if err != nil {
		logger.Log.Error("Failed to build schema info map", "transactionId", txID, "error", err)
		f.failAsyncRequest(txID, fmt.Sprintf("failed to build schema info map: %v", err))
		return
	}

	// Retrieve all provider responses
	var dbResponses []database.AsyncProviderResponse
	dbResponses, err = f.Db.GetAllProviderResponses(txID)
	if err != nil {
		logger.Log.Error("Failed to get all provider responses from DB", "transactionId", txID, "error", err)
		f.failAsyncRequest(txID, fmt.Sprintf("failed to load responses: %v", err))
		return
	}

	federationResponse := &FederationResponse{
		Responses: make([]*ProviderResponse, 0, len(dbResponses)),
	}

	for _, dbResp := range dbResponses {
		var graphqlResp graphql.Response
		if err := json.Unmarshal(dbResp.Payload, &graphqlResp); err != nil {
			logger.Log.Error("Failed to unmarshal provider response payload", "provider", dbResp.ProviderKey, "error", err)
			continue
		}

		federationResponse.Responses = append(federationResponse.Responses, &ProviderResponse{
			ServiceKey: dbResp.ProviderKey,
			Response:   graphqlResp,
		})
	}

	// Accumulate Response back into original query structure
	response := AccumulateResponseWithSchemaInfo(doc, federationResponse, schemaInfoMap)

	mergedPayload, err := json.Marshal(response)
	if err != nil {
		logger.Log.Error("Failed to marshal combined payload", "transactionId", txID, "error", err)
		f.failAsyncRequest(txID, fmt.Sprintf("failed to marshal merged payload: %v", err))
		return
	}

	applied, err := f.Db.CompleteAsyncRequest(txID, mergedPayload)
	if err != nil {
		logger.Log.Error("Failed to complete async request in DB", "transactionId", txID, "error", err)
		return
	}
	if !applied {
		logger.Log.Info("Async request was already finalized by another goroutine, skipping", "transactionId", txID)
		return
	}

	logger.Log.Info("Async query completed and stored successfully", "transactionId", txID)
}

// failAsyncRequest marks the overall async request as failed, logging if it had already
// been finalized (completed or failed) by another goroutine.
func (f *Federator) failAsyncRequest(txID, errMsg string) {
	applied, err := f.Db.FailAsyncRequest(txID, errMsg)
	if err != nil {
		logger.Log.Error("Failed to mark async request as failed", "transactionId", txID, "error", err)
		return
	}
	if !applied {
		logger.Log.Info("Async request was already finalized by another goroutine, skipping failure", "transactionId", txID)
	}
}

// ReceiveProviderCallback handles POST /api/v1/callback
func (f *Federator) ReceiveProviderCallback(w http.ResponseWriter, r *http.Request) {
	txID := r.URL.Query().Get("transactionId")
	providerKey := r.URL.Query().Get("providerKey")

	if txID == "" || providerKey == "" {
		http.Error(w, "Bad request: transactionId and providerKey query parameters are required", http.StatusBadRequest)
		return
	}

	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Log.Error("Failed to read callback request body", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	logger.Log.Info("Received callback from provider", "provider", providerKey, "transactionId", txID)
	f.updateProviderResponseAndCheckCompletion(txID, providerKey, body)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// PollAsyncQueryStatus handles GET /public/graphql/async/{transactionId}
func (f *Federator) PollAsyncQueryStatus(w http.ResponseWriter, r *http.Request) {
	txID := chi.URLParam(r, "transactionId")
	if txID == "" {
		txID = r.URL.Query().Get("transactionId")
	}

	if txID == "" {
		http.Error(w, "Bad request: transactionId is required", http.StatusBadRequest)
		return
	}

	if f.Db == nil {
		http.Error(w, "Internal server error: database not available", http.StatusInternalServerError)
		return
	}

	var asyncReq *database.AsyncRequest
	asyncReq, err := f.Db.GetAsyncRequest(txID)
	if err != nil {
		logger.Log.Error("Failed to get async request", "transactionId", txID, "error", err)
		http.Error(w, fmt.Sprintf("Not found: %v", err), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if asyncReq.Status == "pending" {
		var responses []database.AsyncProviderResponse
		responses, err = f.Db.GetAllProviderResponses(txID)
		var total, completed, pending int
		if err == nil {
			total = len(responses)
			for _, r := range responses {
				if r.Status == "completed" {
					completed++
				} else {
					pending++
				}
			}
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "pending",
			"details": map[string]int{
				"total_providers": total,
				"completed":       completed,
				"pending":         pending,
			},
		})
		return
	}

	if asyncReq.Status == "failed" {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(graphql.Response{
			Data: nil,
			Errors: []interface{}{
				map[string]interface{}{
					"message": fmt.Sprintf("Async execution failed: %s", asyncReq.ErrorMessage.String),
				},
			},
		})
		return
	}

	// Completed: Return the combined payload with status: "completed"
	var payloadMap map[string]interface{}
	if err := json.Unmarshal(asyncReq.CombinedPayload, &payloadMap); err == nil {
		payloadMap["status"] = "completed"
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(payloadMap)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(asyncReq.CombinedPayload)
}

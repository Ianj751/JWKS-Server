package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"

	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Ianj751/handlers"
	"github.com/Ianj751/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleAuth(t *testing.T) {
	// Generate test RSA private keys
	validKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	validKeyBytes := x509.MarshalPKCS1PrivateKey(validKey)

	expiredKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	expiredKeyBytes := x509.MarshalPKCS1PrivateKey(expiredKey)

	// Calculate timestamps for testing
	now := time.Now()
	// Set unexpired time to 1 hour in the future
	unexpiredTime := now.Add(time.Hour).Unix()
	// Set expired time to 1 hour in the past
	expiredTime := now.Add(-time.Hour).Unix()

	tests := []struct {
		name           string
		method         string
		queryParam     string
		mockSetup      func(sqlmock.Sqlmock)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name:       "Valid POST request without expired param",
			method:     http.MethodPost,
			queryParam: "",
			mockSetup: func(mock sqlmock.Sqlmock) {
				// Mock the database response with both expired and unexpired keys
				// The handler will filter for unexpired keys
				rows := sqlmock.NewRows([]string{"kid", "key", "exp"}).
					// This key is not expired (future timestamp)
					AddRow(1, validKeyBytes, unexpiredTime).
					// This key is expired (past timestamp)
					AddRow(2, expiredKeyBytes, expiredTime)

				// Match the exact query used in getDBKey
				mock.ExpectQuery("SELECT \\* FROM keys;").
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"jwt": "", // We can't predict the JWT key, but we can check it exists
			},
		},
		{
			name:       "Valid POST request with expired=true",
			method:     http.MethodPost,
			queryParam: "expired=true",
			mockSetup: func(mock sqlmock.Sqlmock) {
				// Mock the database response with both expired and unexpired keys
				// The handler will filter for expired keys
				rows := sqlmock.NewRows([]string{"kid", "key", "exp"}).
					// This key is not expired (future timestamp)
					AddRow(1, validKeyBytes, unexpiredTime).
					// This key is expired (past timestamp)
					AddRow(2, expiredKeyBytes, expiredTime)

				// Match the exact query used in getDBKey
				mock.ExpectQuery("SELECT \\* FROM keys;").
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"jwt":    "", // We can't predict the JWT key, but we can check it exists
				"expiry": float64(expiredTime),
			},
		},
		{
			name:           "Invalid method (GET)",
			method:         http.MethodGet,
			queryParam:     "",
			mockSetup:      func(mock sqlmock.Sqlmock) {},
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup SQL mock
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			// Configure the mock based on test case
			tc.mockSetup(mock)

			// Create a new request
			url := "/auth"
			if tc.queryParam != "" {
				url = url + "?" + tc.queryParam
			}

			req, err := http.NewRequest(tc.method, url, nil)
			assert.NoError(t, err)

			// Create a ResponseRecorder to record the response
			rr := httptest.NewRecorder()

			// Create the handler with our mock DB
			handler := &handlers.AppHandler{Db: db}

			// Call the handler
			handler.HandleAuth(rr, req)

			// If response doesn't match expected, log the body for debugging
			if rr.Code != tc.expectedStatus {
				t.Logf("Response body: %s", rr.Body.String())
			}

			// Check status code
			assert.Equal(t, tc.expectedStatus, rr.Code)

			// For successful requests, check the response body
			if tc.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				err = json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)

				// Check JWT exists
				assert.Contains(t, response, "jwt")
				assert.NotEmpty(t, response["jwt"])

				// If expecting expiry, check it
				if _, ok := tc.expectedBody["expiry"]; ok {
					assert.Contains(t, response, "expiry")
				}
			}

			// Verify all expected SQL queries were made
			err = mock.ExpectationsWereMet()
			assert.NoError(t, err)
		})
	}
}

func TestHandleJWKS(t *testing.T) {
	validKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	validKeyEnc := x509.MarshalPKCS1PrivateKey(validKey)

	/* 	expiredKey, err := rsa.GenerateKey(rand.Reader, 2048)
	   	require.NoError(t, err)
	   	expiredKeyEnc := x509.MarshalPKCS1PrivateKey(expiredKey) */

	unexpTime := time.Now().Add(time.Hour * 1).Unix()
	//expTime := time.Now().Add(-time.Hour).Unix()

	tests := []struct {
		name           string
		method         string
		mockSetup      func(sqlmock.Sqlmock)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name:   "Valid GET request",
			method: http.MethodGet,
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"kid", "key", "exp"}).
					AddRow(0, validKeyEnc, unexpTime)

				mock.ExpectQuery("SELECT * FROM keys WHERE exp > ?;").
					WithArgs(time.Now().Unix()).
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"alg": "RS256",
				"kty": "RSA",
				"n":   base64.RawURLEncoding.EncodeToString(validKey.N.Bytes()),
				"e":   "AQAB",
				"kid": "0",
				"exp": unexpTime,
			},
		},
		{
			name:           "Invalid method (POST)",
			method:         http.MethodPost,
			mockSetup:      func(s sqlmock.Sqlmock) {},
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			require.NoError(t, err)
			defer db.Close()

			tc.mockSetup(mock)

			url := "./well-known/jwks.json"

			req, err := http.NewRequest(tc.method, url, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()
			handler := &handlers.AppHandler{Db: db}
			handler.HandleJwks(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Logf("Response body: %s", rr.Body.String())
			}
			assert.Equal(t, tc.expectedStatus, rr.Code)

			if tc.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				err = json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				key := response["keys"].([]interface{})[0].(map[string]interface{})

				assert.Contains(t, key, "alg")
				assert.NotEmpty(t, key["alg"])

				assert.Contains(t, key, "kty")
				assert.NotEmpty(t, key["kty"])

				assert.Contains(t, key, "n")
				assert.NotEmpty(t, key["n"])

				assert.Contains(t, key, "e")
				assert.NotEmpty(t, key["e"])

				assert.Contains(t, key, "kid")
				assert.NotEmpty(t, key["kid"])

				assert.Contains(t, key, "exp")
				assert.NotEmpty(t, key["exp"])
			}
		})
	}
}

func TestGenerateDBKeys(t *testing.T) {
	// Test cases
	testCases := []struct {
		name      string
		isExpired bool
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name:      "Success - Unexpired Key",
			isExpired: false,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectPing()
				mock.ExpectExec("INSERT INTO keys (key, exp) VALUES (?, ?);").
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			wantErr: false,
		},
		{
			name:      "Success - Expired Key",
			isExpired: true,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectPing()
				mock.ExpectExec("INSERT INTO keys (key, exp) VALUES (?, ?);").
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name:      "Error - Database Connection Failure",
			isExpired: false,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectPing().WillReturnError(sql.ErrConnDone)
			},
			wantErr: true,
		},
		{
			name:      "Error - Insert Failure",
			isExpired: false,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectPing()
				mock.ExpectExec("INSERT INTO keys (key, exp) VALUES (?, ?);").
					WillReturnError(sql.ErrNoRows)
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new mock database
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual), sqlmock.MonitorPingsOption(true))
			if err != nil {
				t.Fatalf("Failed to create mock database: %v", err)
			}
			defer db.Close()

			// Set up the mock expectations
			tc.mockSetup(mock)

			// Call the function being tested
			err = helpers.GenerateDBKeys(db, tc.isExpired)

			// Check if the error matches expectations
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Make sure all expectations were met
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled expectations: %s", err)
			}
		})
	}
}
func TestGenerateRSA(t *testing.T) {
	//Ensure that RSA Keys are not invalid
	//Reference RFC 8017
	key, err := helpers.GenerateRSAKeys()
	if err != nil || key == nil {
		t.Fatal("error generating rsa keys: ", err)
	}

	// n    the RSA modulus, a positive integer
	if key.N.Sign() != 1 {
		t.Error("invalid modulus")

	}
	// d   the RSA private exponent, a positive integer
	if key.D.Sign() != 1 {
		t.Error("invalid private exponent: ")
	}

	// e    the RSA public exponent, a positive integer
	/*, and the RSA
	  public exponent e is an integer between 3 and n - 1... */
	if key.E < 0 || key.E < 3 {
		t.Error("invalid public exponent, was not positive")
	}

	/* RFC 8017: In a valid RSA public key, the RSA modulus n is a product of u
	   distinct odd primes r_i, i = 1, 2, ..., u, where u >= 2...*/
	if len(key.Primes) < 2 {
		t.Error("not enough prime factors")
	}

	// Check if the key is valid by reconstructing some components

	if err := key.Validate(); err != nil {
		t.Errorf("key validation failed: %v", err)
	}

}

func TestMain(m *testing.M) {
	// call flag.Parse() here if TestMain uses flags
	m.Run()
}

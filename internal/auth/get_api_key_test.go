package auth

import (
	"net/http" 
	"testing"
	"errors"
)

var wrongApiKeyErr = errors.New("malformed authorization header")

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		input   http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "Empty authorization value",
			input:   http.Header{"Authorization": {""}},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "Missing authorization header",
			input:   http.Header{},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "Valid short API key",
			input:   http.Header{"Authorization": {"ApiKey xy"}},
			wantKey: "xy",
		},
		{
			name:    "Bearer token instead of API key",
			input:   http.Header{"Authorization": {"Bearer xyz1234"}},
			wantErr: wrongApiKeyErr,
		},
		{
			name:    "Bearer ApiKey",
			input:   http.Header{"Authorization": {"Bearer ApiKey"}},
			wantErr: wrongApiKeyErr,
		},
		{
			name:  "Empty API key",
			input: http.Header{"Authorization": {"ApiKey "}},
		},
		{
			name:    "Valid API key",
			input:   http.Header{"Authorization": {"ApiKey test1234"}},
			wantKey: "test1234",
		},
		{
			name:    "Misspelled authorization header",
			input:   http.Header{"Authorizatio": {"ApiKey test1234"}},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "Invalid authorization format",
			input:   http.Header{"Authorization": {"A"}},
			wantErr: wrongApiKeyErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tc.input)

			if gotKey != tc.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tc.wantKey)
			}
			
			if gotErr != nil && tc.wantErr != nil {
			    if gotErr.Error() != tc.wantErr.Error() {
				t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tc.wantErr)
			    }
			} else if gotErr != tc.wantErr {
			    t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tc.wantErr)
			}
		})
	}
}

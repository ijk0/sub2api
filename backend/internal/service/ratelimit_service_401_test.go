//go:build unit

package service

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type rateLimitAccountRepoStub struct {
	mockAccountRepoForGemini
	setErrorCalls int
	tempCalls     int
	lastErrorMsg  string
}

func (r *rateLimitAccountRepoStub) SetError(ctx context.Context, id int64, errorMsg string) error {
	r.setErrorCalls++
	r.lastErrorMsg = errorMsg
	return nil
}

func (r *rateLimitAccountRepoStub) SetTempUnschedulable(ctx context.Context, id int64, until time.Time, reason string) error {
	r.tempCalls++
	return nil
}

type tokenCacheInvalidatorRecorder struct {
	accounts []*Account
	err      error
}

func (r *tokenCacheInvalidatorRecorder) InvalidateToken(ctx context.Context, account *Account) error {
	r.accounts = append(r.accounts, account)
	return r.err
}

func TestRateLimitService_HandleUpstreamError_OAuth401SetsTempUnschedulable(t *testing.T) {
	t.Run("gemini", func(t *testing.T) {
		repo := &rateLimitAccountRepoStub{}
		invalidator := &tokenCacheInvalidatorRecorder{}
		service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
		service.SetTokenCacheInvalidator(invalidator)
		account := &Account{
			ID:       100,
			Platform: PlatformGemini,
			Type:     AccountTypeOAuth,
			Credentials: map[string]any{
				"temp_unschedulable_enabled": true,
				"temp_unschedulable_rules": []any{
					map[string]any{
						"error_code":       401,
						"keywords":         []any{"unauthorized"},
						"duration_minutes": 30,
						"description":      "custom rule",
					},
				},
			},
		}

		shouldDisable := service.HandleUpstreamError(context.Background(), account, 401, http.Header{}, []byte("unauthorized"))

		require.True(t, shouldDisable)
		require.Equal(t, 0, repo.setErrorCalls)
		require.Equal(t, 1, repo.tempCalls)
		require.Len(t, invalidator.accounts, 1)
	})

	t.Run("antigravity_401_uses_SetError", func(t *testing.T) {
		// Antigravity 401 由 applyErrorPolicy 的 temp_unschedulable_rules 控制，
		// HandleUpstreamError 中走 SetError 路径。
		repo := &rateLimitAccountRepoStub{}
		invalidator := &tokenCacheInvalidatorRecorder{}
		service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
		service.SetTokenCacheInvalidator(invalidator)
		account := &Account{
			ID:       100,
			Platform: PlatformAntigravity,
			Type:     AccountTypeOAuth,
		}

		shouldDisable := service.HandleUpstreamError(context.Background(), account, 401, http.Header{}, []byte("unauthorized"))

		require.True(t, shouldDisable)
		require.Equal(t, 1, repo.setErrorCalls)
		require.Equal(t, 0, repo.tempCalls)
		require.Empty(t, invalidator.accounts)
	})
}

func TestRateLimitService_HandleUpstreamError_OAuth401InvalidatorError(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	invalidator := &tokenCacheInvalidatorRecorder{err: errors.New("boom")}
	service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	service.SetTokenCacheInvalidator(invalidator)
	account := &Account{
		ID:       101,
		Platform: PlatformGemini,
		Type:     AccountTypeOAuth,
	}

	shouldDisable := service.HandleUpstreamError(context.Background(), account, 401, http.Header{}, []byte("unauthorized"))

	require.True(t, shouldDisable)
	require.Equal(t, 0, repo.setErrorCalls)
	require.Equal(t, 1, repo.tempCalls)
	require.Len(t, invalidator.accounts, 1)
}

func TestRateLimitService_HandleUpstreamError_NonOAuth401(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	invalidator := &tokenCacheInvalidatorRecorder{}
	service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	service.SetTokenCacheInvalidator(invalidator)
	account := &Account{
		ID:       102,
		Platform: PlatformOpenAI,
		Type:     AccountTypeAPIKey,
	}

	shouldDisable := service.HandleUpstreamError(context.Background(), account, 401, http.Header{}, []byte("unauthorized"))

	require.True(t, shouldDisable)
	require.Equal(t, 1, repo.setErrorCalls)
	require.Empty(t, invalidator.accounts)
}

func TestRateLimitService_HandleUpstreamError_OAuth401EscalatesToError(t *testing.T) {
	t.Run("repeat_401_plain_text_reason", func(t *testing.T) {
		// Simulates: first 401 set temp_unschedulable with "OAuth 401: ..." reason,
		// cooldown expired, account got 401 again → should escalate to permanent error.
		repo := &rateLimitAccountRepoStub{}
		invalidator := &tokenCacheInvalidatorRecorder{}
		svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
		svc.SetTokenCacheInvalidator(invalidator)
		account := &Account{
			ID:                      200,
			Platform:                PlatformOpenAI,
			Type:                    AccountTypeOAuth,
			TempUnschedulableReason: "OAuth 401: Your authentication token has been invalidated.",
		}

		shouldDisable := svc.HandleUpstreamError(context.Background(), account, 401, http.Header{},
			[]byte(`{"error":{"message":"Your authentication token has been invalidated.","code":"token_invalidated"}}`))

		require.True(t, shouldDisable)
		require.Equal(t, 1, repo.setErrorCalls, "should call SetError for permanent disable")
		require.Equal(t, 0, repo.tempCalls, "should NOT call SetTempUnschedulable")
		require.Contains(t, repo.lastErrorMsg, "permanently failed")
		require.Empty(t, invalidator.accounts, "should NOT invalidate cache on escalation")
	})

	t.Run("repeat_401_auth_failed_reason", func(t *testing.T) {
		repo := &rateLimitAccountRepoStub{}
		svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
		account := &Account{
			ID:                      201,
			Platform:                PlatformGemini,
			Type:                    AccountTypeOAuth,
			TempUnschedulableReason: "Authentication failed (401): invalid or expired credentials",
		}

		shouldDisable := svc.HandleUpstreamError(context.Background(), account, 401, http.Header{}, []byte("unauthorized"))

		require.True(t, shouldDisable)
		require.Equal(t, 1, repo.setErrorCalls)
		require.Equal(t, 0, repo.tempCalls)
	})

	t.Run("first_401_no_escalation", func(t *testing.T) {
		// No previous 401 reason → should do normal temp_unschedulable, not escalate.
		repo := &rateLimitAccountRepoStub{}
		invalidator := &tokenCacheInvalidatorRecorder{}
		svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
		svc.SetTokenCacheInvalidator(invalidator)
		account := &Account{
			ID:                      202,
			Platform:                PlatformOpenAI,
			Type:                    AccountTypeOAuth,
			TempUnschedulableReason: "", // no previous 401
		}

		shouldDisable := svc.HandleUpstreamError(context.Background(), account, 401, http.Header{},
			[]byte(`{"error":{"message":"Your authentication token has been invalidated.","code":"token_invalidated"}}`))

		require.True(t, shouldDisable)
		require.Equal(t, 0, repo.setErrorCalls, "first 401 should NOT permanently disable")
		require.Equal(t, 1, repo.tempCalls, "first 401 should set temp_unschedulable")
		require.Len(t, invalidator.accounts, 1)
	})

	t.Run("previous_non_401_reason_no_escalation", func(t *testing.T) {
		// Previous temp_unschedulable was for a different reason (e.g. 429) → no escalation.
		repo := &rateLimitAccountRepoStub{}
		invalidator := &tokenCacheInvalidatorRecorder{}
		svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
		svc.SetTokenCacheInvalidator(invalidator)
		account := &Account{
			ID:                      203,
			Platform:                PlatformOpenAI,
			Type:                    AccountTypeOAuth,
			TempUnschedulableReason: "Rate limited (429): too many requests",
		}

		shouldDisable := svc.HandleUpstreamError(context.Background(), account, 401, http.Header{}, []byte("unauthorized"))

		require.True(t, shouldDisable)
		require.Equal(t, 0, repo.setErrorCalls, "non-401 previous reason should NOT escalate")
		require.Equal(t, 1, repo.tempCalls)
	})
}

func TestIsOAuth401Reason(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		want   bool
	}{
		{"empty", "", false},
		{"oauth_401_prefix", "OAuth 401: token invalidated", true},
		{"auth_failed_401_prefix", "Authentication failed (401): invalid or expired credentials", true},
		{"non_401_reason", "Rate limited (429): too many requests", false},
		{"json_state_401", `{"status_code":401,"matched_keyword":"unauthorized"}`, true},
		{"json_state_non_401", `{"status_code":429,"matched_keyword":"rate_limit"}`, false},
		{"random_text", "some random reason", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isOAuth401Reason(tt.reason))
		})
	}
}

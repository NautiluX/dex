package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

func groupTestConnector(t testing.TB, limit int, handler http.HandlerFunc) *googleConnector {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	service, err := admin.NewService(context.Background(), option.WithoutAuthentication(), option.WithEndpoint(server.URL))
	require.NoError(t, err)
	return &googleConnector{
		logger:             slog.New(slog.DiscardHandler),
		adminSrv:           map[string]*admin.Service{wildcardDomainToAdminEmail: service},
		groupLookupSlots:   make(chan struct{}, limit),
		groupLookupLimiter: rate.NewLimiter(rate.Inf, 1),
	}
}

func writeGroupPage(w http.ResponseWriter, emails []string, next string) {
	page := admin.Groups{NextPageToken: next}
	for _, email := range emails {
		page.Groups = append(page.Groups, &admin.Group{Email: email})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(page)
}

func TestGroupLookupGraph(t *testing.T) {
	for _, limit := range []int{1, 5} {
		for _, transitive := range []bool{false, true} {
			t.Run(fmt.Sprintf("limit=%d/transitive=%t", limit, transitive), func(t *testing.T) {
				t.Parallel()
				var mu sync.Mutex
				calls := map[string]int{}
				conn := groupTestConnector(t, limit, func(w http.ResponseWriter, r *http.Request) {
					key := r.URL.Query().Get("userKey")
					page := r.URL.Query().Get("pageToken")
					mu.Lock()
					calls[key+":"+page]++
					mu.Unlock()
					switch key {
					case "user@example.com":
						if page == "" {
							writeGroupPage(w, []string{"a@example.com", "b@example.com"}, "next")
						} else {
							writeGroupPage(w, []string{"a@example.com", "c@example.com"}, "")
						}
					case "a@example.com", "b@example.com", "c@example.com":
						writeGroupPage(w, []string{"parent@example.com"}, "")
					case "parent@example.com":
						// A cycle and a shared parent must not trigger duplicate fetches.
						writeGroupPage(w, []string{"a@example.com"}, "")
					default:
						http.Error(w, "unexpected member", http.StatusBadRequest)
					}
				})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				groups, err := conn.getGroups(ctx, "user@example.com", transitive)
				require.NoError(t, err)
				want := []string{"a@example.com", "b@example.com", "c@example.com"}
				if transitive {
					want = append(want, "parent@example.com")
				}
				require.Equal(t, want, groups)
				mu.Lock()
				defer mu.Unlock()
				wantCalls := map[string]int{"user@example.com:": 1, "user@example.com:next": 1}
				if transitive {
					for _, group := range want {
						wantCalls[group+":"] = 1
					}
				}
				require.Equal(t, wantCalls, calls)
			})
		}
	}
}

func TestGroupLookupSharedConcurrencyLimit(t *testing.T) {
	for _, logins := range []int{1, 4} {
		t.Run(fmt.Sprintf("logins=%d", logins), func(t *testing.T) {
			const limit = 2
			started := make(chan struct{}, 16)
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			conn := groupTestConnector(t, limit, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("userKey") == "user@example.com" {
					writeGroupPage(w, []string{"a@example.com", "b@example.com", "c@example.com"}, "")
					return
				}
				started <- struct{}{}
				select {
				case <-release:
					writeGroupPage(w, nil, "")
				case <-r.Context().Done():
				}
			})
			t.Cleanup(unblock)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, logins)
			for i := 0; i < logins; i++ {
				go func() {
					_, err := conn.getGroups(ctx, "user@example.com", true)
					done <- err
				}()
			}
			for i := 0; i < limit; i++ {
				select {
				case <-started:
				case <-ctx.Done():
					t.Fatal("requests did not run concurrently")
				}
			}
			select {
			case <-started:
				t.Fatal("concurrent logins exceeded the connector-wide limit")
			case <-time.After(50 * time.Millisecond):
			}
			unblock()
			for i := 0; i < logins; i++ {
				require.NoError(t, <-done)
			}
		})
	}
}

func TestGroupLookupCancellation(t *testing.T) {
	for _, waitingForSlot := range []bool{false, true} {
		t.Run(fmt.Sprintf("waitingForSlot=%t", waitingForSlot), func(t *testing.T) {
			started := make(chan struct{})
			conn := groupTestConnector(t, 1, func(w http.ResponseWriter, r *http.Request) {
				close(started)
				<-r.Context().Done()
			})
			if waitingForSlot {
				conn.groupLookupSlots <- struct{}{}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				groups, err := conn.getGroups(ctx, "user@example.com", true)
				if groups != nil {
					err = errors.New("cancelled lookup returned partial groups")
				}
				done <- err
			}()
			if !waitingForSlot {
				select {
				case <-started:
				case <-time.After(5 * time.Second):
					t.Fatal("request did not start")
				}
			}
			cancel()
			select {
			case err := <-done:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(5 * time.Second):
				t.Fatal("cancellation did not stop lookup workers")
			}
		})
	}
}

func TestGroupLookupErrorCancelsSiblings(t *testing.T) {
	siblingStarted := make(chan struct{})
	siblingCancelled := make(chan struct{})
	conn := groupTestConnector(t, 2, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("userKey") {
		case "user@example.com":
			writeGroupPage(w, []string{"a@example.com", "b@example.com"}, "")
		case "a@example.com":
			select {
			case <-siblingStarted:
				http.Error(w, "failed lookup", http.StatusBadRequest)
			case <-r.Context().Done():
			}
		case "b@example.com":
			close(siblingStarted)
			<-r.Context().Done()
			close(siblingCancelled)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	groups, err := conn.getGroups(ctx, "user@example.com", true)
	require.ErrorContains(t, err, "failed lookup")
	require.Nil(t, groups)
	select {
	case <-siblingCancelled:
	case <-ctx.Done():
		t.Fatal("failed lookup did not cancel its sibling request")
	}
}

func TestGroupLookupRequestRate(t *testing.T) {
	starts := make(chan time.Time, 3)
	conn := groupTestConnector(t, 3, func(w http.ResponseWriter, r *http.Request) {
		starts <- time.Now()
		writeGroupPage(w, nil, "")
	})
	conn.groupLookupLimiter = rate.NewLimiter(20, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func() {
			_, err := conn.getGroups(ctx, "user@example.com", true)
			done <- err
		}()
	}
	for i := 0; i < 3; i++ {
		require.NoError(t, <-done)
	}
	first, second, third := <-starts, <-starts, <-starts
	// Allow scheduling noise; three requests at 20/s need two intervals.
	require.GreaterOrEqual(t, third.Sub(first), 90*time.Millisecond)
	require.True(t, second.Before(third))
}

func TestGroupQuotaErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"success", nil, false},
		{"transport", errors.New("network failure"), false},
		{"429", &googleapi.Error{Code: 429}, true},
		{"user quota", &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "userRateLimitExceeded"}}}, true},
		{"account quota", &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "rateLimitExceeded"}}}, true},
		{"permission denied", &googleapi.Error{Code: 403, Errors: []googleapi.ErrorItem{{Reason: "forbidden"}}}, false},
		{"bad request", &googleapi.Error{Code: 400}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, isGroupQuotaError(tc.err))
		})
	}
}

func TestGroupLookupQuotaRetryKeepsPageToken(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	conn := groupTestConnector(t, 1, func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("pageToken")
		mu.Lock()
		calls[page]++
		n := calls[page]
		mu.Unlock()
		if page == "" {
			writeGroupPage(w, []string{"a@example.com"}, "next")
		} else if n == 1 {
			http.Error(w, "quota exceeded", http.StatusTooManyRequests)
		} else {
			writeGroupPage(w, []string{"b@example.com"}, "")
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	groups, err := conn.getGroups(ctx, "user@example.com", false)
	require.NoError(t, err)
	require.Equal(t, []string{"a@example.com", "b@example.com"}, groups)
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, map[string]int{"": 1, "next": 2}, calls)
}

func TestGroupLookupQuotaRetriesAreBounded(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	conn := groupTestConnector(t, 1, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		http.Error(w, "quota exceeded", http.StatusTooManyRequests)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	groups, err := conn.getGroups(ctx, "user@example.com", true)
	require.ErrorContains(t, err, "quota exceeded")
	require.Nil(t, groups)
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, maxGroupLookupAttempts, calls)
	require.Empty(t, conn.groupLookupSlots)
}

func TestGroupLookupRateWaitCancels(t *testing.T) {
	conn := groupTestConnector(t, 1, func(w http.ResponseWriter, r *http.Request) {
		t.Error("cancelled rate wait must not issue an API request")
		writeGroupPage(w, nil, "")
	})
	conn.groupLookupLimiter = rate.NewLimiter(rate.Every(time.Hour), 1)
	require.True(t, conn.groupLookupLimiter.Allow())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := conn.getGroups(ctx, "user@example.com", true)
		done <- err
	}()
	// Observe acquisition of the API slot, proving cancellation interrupts the
	// limiter wait rather than only cancelling before worker dispatch.
	require.Eventually(t, func() bool { return len(conn.groupLookupSlots) == 1 }, time.Second, time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("rate wait did not cancel")
	}
	require.Empty(t, conn.groupLookupSlots)
}

func TestGroupLookupBackoffCancels(t *testing.T) {
	responded := make(chan struct{}, 4)
	conn := groupTestConnector(t, 1, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "quota exceeded", http.StatusTooManyRequests)
		w.(http.Flusher).Flush()
		responded <- struct{}{}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := conn.getGroups(ctx, "user@example.com", true)
		done <- err
	}()
	select {
	case <-responded:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	// The slot is released after the quota response, before the retry timer.
	require.Eventually(t, func() bool { return len(conn.groupLookupSlots) == 0 }, time.Second, time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("backoff did not cancel")
	}
	require.Empty(t, responded, "cancelled lookup must not retry")
}

func BenchmarkGroupLookup(b *testing.B) {
	for _, limit := range []int{1, 5} {
		b.Run(fmt.Sprintf("concurrency=%d", limit), func(b *testing.B) {
			conn := groupTestConnector(b, limit, func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(2 * time.Millisecond)
				var groups []string
				if r.URL.Query().Get("userKey") == "user@example.com" {
					for i := 0; i < 32; i++ {
						groups = append(groups, fmt.Sprintf("group%d@example.com", i))
					}
				}
				writeGroupPage(w, groups, "")
			})
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				groups, err := conn.getGroups(context.Background(), "user@example.com", true)
				if err != nil || len(groups) != 32 {
					b.Fatalf("groups=%d err=%v", len(groups), err)
				}
			}
		})
	}
}

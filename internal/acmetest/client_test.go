package acmetest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHeadResponses(t *testing.T) {
	for _, status := range []int{200, 400, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Replay-Nonce", "bm9uY2U")
				w.Header().Set("Content-Type", "application/json")
				body := `{}`
				if status >= 400 {
					w.Header().Set("Content-Type", "application/problem+json")
					body = `{"type":"urn:ietf:params:acme:error:serverInternal","detail":"test error"}`
				}
				w.WriteHeader(status)
				fmt.Fprint(w, body)
			}))
			const dirURL = "https://ca.test/directory"
			c := NewClient(t, srv.Client(), dirURL)
			resp := c.Do(&Request{Method: "HEAD", URL: dirURL})
			if resp.StatusCode != status || len(resp.Body) != 0 || resp.JSON != nil || resp.Problem != nil {
				t.Fatalf("unexpected HEAD response: %+v", resp)
			}
		})
	}
}

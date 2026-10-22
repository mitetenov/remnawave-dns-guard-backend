package guard

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(value any, status int) *http.Response {
	b, _ := json.Marshal(value)
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(b))}
}
func testConfig(path string) Config {
	return Config{Username: "admin", Password: "password", AppSecret: strings.Repeat("S", 32), AgentToken: strings.Repeat("T", 32), DatabasePath: path, PublicOrigin: "http://testserver", CloudflareAPIToken: "hidden-token"}
}

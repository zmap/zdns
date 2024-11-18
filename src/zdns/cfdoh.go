package zdns

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

// CFClient represents a client for making DNS-over-HTTPS requests
type CFClient struct {
	httpClient *http.Client
	baseURL    string
}

// CFResponse represents the structure of the JSON response from the DNS-over-HTTPS API
type CFResponse struct {
	Error      string       `json:"Error"`
	Status     int          `json:"Status"`
	TC         bool         `json:"TC"`
	RD         bool         `json:"RD"`
	RA         bool         `json:"RA"`
	AD         bool         `json:"AD"`
	CD         bool         `json:"CD"`
	CFQuestion []CFQuestion `json:"Question"`
	CFAnswer   []CFAnswer   `json:"Answer"`
	Comment    interface{}  `json:"Comment"` // Can be string or an array
}

// CFQuestion represents the CFQuestion section in the DNS response
type CFQuestion struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

// CFAnswer represents the CFAnswer section in the DNS response
type CFAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

// NewCFClient initializes a new DNSClient with HTTP/2 support
func NewCFClient(baseURL string) *CFClient {
	transport := &http2.Transport{}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 10,
	}

	return &CFClient{
		httpClient: httpClient,
		baseURL:    baseURL,
	}
}

// MakeDNSRequest sends a DNS query to the DNS-over-HTTPS API
func (c *CFClient) MakeDNSRequest(name string, queryType uint16) *CFResponse {
	// Construct the URL with query parameters
	url := fmt.Sprintf("%s?do=1&name=%s&type=%d", c.baseURL, name, queryType)

	// Create an HTTP GET request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return &CFResponse{Error: fmt.Sprintf("failed to create request: %v", err)}
	}
	req.Header.Set("Accept", "application/dns-json")

	// Send the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &CFResponse{Error: fmt.Sprintf("failed to send request: %v", err)}
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return &CFResponse{Error: fmt.Sprintf("failed to read response body: %v", err)}
	}

	// Check if the HTTP status code is 200
	if resp.StatusCode != http.StatusOK {
		return &CFResponse{Error: fmt.Sprintf("HTTP request failed with status code: %d", resp.StatusCode)}
	}

	// Parse the JSON response
	var dnsResponse CFResponse
	err = json.Unmarshal(body, &dnsResponse)
	if err != nil {
		return &CFResponse{Error: fmt.Sprintf("failed to unmarshal JSON response: %v", err)}
	}

	return &dnsResponse
}

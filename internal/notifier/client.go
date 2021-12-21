package notifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"

	"github.com/Issif/falco-talon/internal/utils"
)

var ErrHeaderMissing = errors.New("missing header")                   // ErrHeaderMissing = 400
var ErrClientAuthenticationError = errors.New("authentication Error") // ErrClientAuthenticationError = 401
var ErrForbidden = errors.New("access Denied")                        // ErrForbidden = 403
var ErrNotFound = errors.New("resource not found")                    // ErrNotFound = 404
var ErrUnprocessableEntityError = errors.New("bad Request")           // ErrUnprocessableEntityError = 422
var ErrTooManyRequest = errors.New("exceeding post rate limit")       // ErrTooManyRequest = 429

const DefaultContentType = "application/json; charset=utf-8"
const UserAgent = "Falco-Talon"

type HTTPClient struct {
	URL         *url.URL
	ContentType string
}

func NewHTTPClient(u string) (*HTTPClient, error) {
	reg := regexp.MustCompile(`(http)(s?)://.*`)
	if !reg.MatchString(u) {
		return nil, errors.New("invalid url")
	}
	if _, err := url.ParseRequestURI(u); err != nil {
		return nil, errors.New("invalid url")
	}
	URL, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	return &HTTPClient{URL: URL, ContentType: DefaultContentType}, nil
}

func (c *HTTPClient) Post(payload interface{}) error {
	// defer + recover to catch panic if output doesn't respond
	defer func() {
		if err := recover(); err != nil {
			utils.PrintLog("error", fmt.Sprintf("in recover: %v", err))
		}
	}()

	body := new(bytes.Buffer)
	if err := json.NewEncoder(body).Encode(payload); err != nil {
		return err
	}

	client := &http.Client{
		Transport: http.DefaultTransport.(*http.Transport).Clone(),
	}

	req, err := http.NewRequest("POST", c.URL.String(), body)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", c.ContentType)
	req.Header.Add("User-Agent", UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent: // 200, 201, 202, 204
		return nil
	case http.StatusBadRequest: // 400
		return ErrHeaderMissing
	case http.StatusUnauthorized: // 401
		return ErrClientAuthenticationError
	case http.StatusForbidden: // 403
		return ErrForbidden
	case http.StatusNotFound: // 404
		return ErrNotFound
	case http.StatusUnprocessableEntity: // 422
		return ErrUnprocessableEntityError
	case http.StatusTooManyRequests: // 429
		return ErrTooManyRequest
	default:
		return errors.New(resp.Status)
	}
}

package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	maxResponse = 2 << 20
	maxRequest  = 64 << 10 // server MaxBytesReader
)

// apiError is a definite server answer: the request was received and refused.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string { return fmt.Sprintf("AllowIt returned HTTP %d: %s", e.Status, e.Message) }

// uncertainError means the request may or may not have been processed.
type uncertainError struct{ Err error }

func (e *uncertainError) Error() string { return e.Err.Error() }

// configError means nothing was processed because the connection itself is
// misconfigured (TLS trust, redirect).
type configError struct{ Err error }

func (e *configError) Error() string { return e.Err.Error() }

type client struct {
	cfg     *Config
	http    *http.Client
	timeout time.Duration
	retries int
	sleep   func(time.Duration)
}

func newClient(cfg *Config, timeout time.Duration, sleep func(time.Duration)) (*client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil || !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ALLOWIT_CA_FILE must name a readable PEM certificate file")
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	return &client{
		cfg: cfg,
		// Never follow redirects: the Authorization header must stay on the configured origin.
		http:    &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		timeout: timeout,
		retries: 2,
		sleep:   sleep,
	}, nil
}

func (c *client) endpoint(action string) string {
	return c.cfg.Origin + "/api/harness/" + c.cfg.Owner + "/" + c.cfg.Policy + "/" + action
}

// call performs one harness request. Transport failures and gateway errors are
// retried with the identical body; the server deduplicates by requestId.
func (c *client) call(method, action string, body []byte, out any) error {
	if len(body) > maxRequest {
		return errors.New("request is larger than the 64 KB limit")
	}
	var last error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			c.sleep(time.Duration(attempt) * time.Second)
		}
		status, data, err := c.once(method, action, body)
		if err != nil {
			var ce *configError
			if errors.As(err, &ce) {
				return err
			}
			last = err
			continue
		}
		if status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout {
			last = &uncertainError{&apiError{status, errorMessage(data)}}
			continue
		}
		if status >= 300 && status < 400 {
			return &configError{fmt.Errorf("AllowIt answered with a redirect (HTTP %d); check ALLOWIT_URL", status)}
		}
		if status != http.StatusOK {
			if status >= 500 {
				return &uncertainError{&apiError{status, errorMessage(data)}}
			}
			return &apiError{status, errorMessage(data)}
		}
		d := json.NewDecoder(bytes.NewReader(data))
		d.UseNumber()
		if err := d.Decode(out); err != nil || d.Decode(new(any)) != io.EOF {
			return &uncertainError{errors.New("AllowIt returned a response that is not valid JSON")}
		}
		return nil
	}
	var ue *uncertainError
	if errors.As(last, &ue) {
		return last
	}
	return &uncertainError{last}
}

func (c *client) once(method, action string, body []byte) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(action), reader)
	if err != nil {
		return 0, nil, &configError{errors.New("could not build the AllowIt request")}
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "allowit-cli/"+Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		var cert *tls.CertificateVerificationError
		var unknown x509.UnknownAuthorityError
		var hostname x509.HostnameError
		if errors.As(err, &cert) || errors.As(err, &unknown) || errors.As(err, &hostname) {
			return 0, nil, &configError{errors.New("TLS certificate for ALLOWIT_URL is not trusted")}
		}
		return 0, nil, &uncertainError{fmt.Errorf("network error talking to AllowIt: %v", err)}
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if err != nil {
		return 0, nil, &uncertainError{fmt.Errorf("network error reading the AllowIt response: %v", err)}
	}
	if len(data) > maxResponse {
		return 0, nil, &uncertainError{errors.New("AllowIt response exceeded the 2 MB limit")}
	}
	return res.StatusCode, data, nil
}

func errorMessage(data []byte) string {
	var v struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &v) == nil && v.Error != "" {
		return v.Error
	}
	return "no error message"
}

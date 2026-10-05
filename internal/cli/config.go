package cli

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Config is read from the environment only. The token never comes from a flag
// or URL, so it cannot land in shell history, process listings or logs.
type Config struct {
	Origin string
	Owner  string
	Policy string
	Secret string
	Token  string
	CAFile string
}

// AllowIt issues 32-character URL-safe secrets; 16 is a floor that keeps the
// secret-part redaction in scrubber from matching ordinary short words.
var (
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	secretPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

func loadConfig(getenv func(string) string) (*Config, error) {
	origin, err := parseOrigin(getenv("ALLOWIT_URL"))
	if err != nil {
		return nil, err
	}
	owner, policy, secret, err := parseToken(getenv("ALLOWIT_TOKEN"))
	if err != nil {
		return nil, err
	}
	return &Config{Origin: origin, Owner: owner, Policy: policy, Secret: secret, Token: owner + "." + policy + "." + secret, CAFile: getenv("ALLOWIT_CA_FILE")}, nil
}

// parseOrigin accepts exactly scheme://host[:port]. HTTPS is required except
// for loopback hosts, which exist only for local development and tests.
func parseOrigin(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("set ALLOWIT_URL to the AllowIt service origin, e.g. https://allowit.example")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return "", errors.New("ALLOWIT_URL must be an origin such as https://allowit.example")
	}
	if u.User != nil {
		return "", errors.New("ALLOWIT_URL must not contain credentials")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "?#") {
		return "", errors.New("ALLOWIT_URL must be an origin without a path, query or fragment")
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
	case "http":
		if !loopback(u.Hostname()) {
			return "", errors.New("ALLOWIT_URL must use https (http is allowed only for localhost)")
		}
	default:
		return "", errors.New("ALLOWIT_URL must use https")
	}
	host := strings.ToLower(u.Host)
	if port := u.Port(); scheme == "https" && port == "443" || scheme == "http" && port == "80" {
		host = strings.ToLower(u.Hostname())
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	return scheme + "://" + host, nil
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func parseToken(raw string) (owner, policy, secret string, err error) {
	if raw == "" {
		return "", "", "", errors.New("set ALLOWIT_TOKEN to the policy's harness token")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || !idPattern.MatchString(parts[0]) || !idPattern.MatchString(parts[1]) || !secretPattern.MatchString(parts[2]) {
		return "", "", "", errors.New("ALLOWIT_TOKEN must have the form owner.policy.secret")
	}
	return parts[0], parts[1], parts[2], nil
}

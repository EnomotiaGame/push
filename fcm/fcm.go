/*
Package fcm sends notifications to Android and iOS apps through Firebase Cloud
Messaging's HTTP v1 API, with the Go standard library and nothing else.

Firebase hands an Android message to Google's own push service and an iPhone's
to Apple's, using the APNs key uploaded to the Firebase project. One sender,
one credential, two platforms.

The protocol is one authenticated POST per message. The credential is a Google
service-account key file, traded for an hour-long access token by signing a
JWT (RFC 7523). That takes a few dozen lines, so this package does it itself
instead of pulling a Google client library onto the path of every message.

	sa, _ := fcm.LoadServiceAccount("firebase-key.json")
	client := fcm.New(sa)
	res, err := client.Send(ctx, deviceToken, fcm.Message{
		Title: "Your order shipped",
		Body:  "It arrives on Friday.",
		Data:  map[string]string{"url": "/orders/42"},
		TTL:   time.Hour,
	})
	switch res.Outcome {
	case fcm.Gone:      // delete the token
	case fcm.Transient: // retry after res.RetryAfter
	case fcm.Unsent:    // fix your credentials; the device is fine
	}

Messages through Firebase are not end-to-end encrypted: Google, and Apple for
an iPhone, can read them. Put on the lock screen only what you would show
there anyway.
*/
package fcm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Scope is the one OAuth permission the access token asks for.
const Scope = "https://www.googleapis.com/auth/firebase.messaging"

// DefaultBaseURL is Firebase's own address.
const DefaultBaseURL = "https://fcm.googleapis.com"

// DefaultTokenURL is Google's token endpoint, used when the key file names none.
const DefaultTokenURL = "https://oauth2.googleapis.com/token"

// ErrNoServiceAccount is LoadServiceAccount given an empty path.
var ErrNoServiceAccount = errors.New("fcm: no service account configured")

var b64 = base64.RawURLEncoding

// ServiceAccount is the part of a Google service-account key file the sender
// needs: the JSON file the Firebase console downloads under Project settings,
// Service accounts.
type ServiceAccount struct {
	Type        string `json:"type"`
	ProjectID   string `json:"project_id"`
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
	TokenURI    string `json:"token_uri"`
	key         *rsa.PrivateKey
}

// LoadServiceAccount reads a service-account key file. An empty path is
// ErrNoServiceAccount. Errors name the path and the reason, never the file's
// contents.
func LoadServiceAccount(path string) (ServiceAccount, error) {
	if strings.TrimSpace(path) == "" {
		return ServiceAccount{}, ErrNoServiceAccount
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ServiceAccount{}, fmt.Errorf("fcm: service account: %w", err)
	}
	return ParseServiceAccount(raw)
}

// ParseServiceAccount reads a service-account key file's bytes. The private
// key is kept parsed; the PrivateKey text field is cleared.
func ParseServiceAccount(raw []byte) (ServiceAccount, error) {
	var sa ServiceAccount
	if err := json.Unmarshal(raw, &sa); err != nil {
		return ServiceAccount{}, errors.New("fcm: service account: not a JSON key file")
	}
	if sa.Type != "" && sa.Type != "service_account" {
		return ServiceAccount{}, fmt.Errorf("fcm: service account: type %q is not a service account", sa.Type)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return ServiceAccount{}, errors.New("fcm: service account: client_email and private_key are required")
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return ServiceAccount{}, errors.New("fcm: service account: private_key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		k1, err1 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err1 != nil {
			return ServiceAccount{}, errors.New("fcm: service account: private_key does not parse")
		}
		parsed = k1
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return ServiceAccount{}, errors.New("fcm: service account: private_key is not an RSA key")
	}
	sa.key = key
	if sa.TokenURI == "" {
		sa.TokenURI = DefaultTokenURL
	}
	sa.PrivateKey = ""
	return sa, nil
}

// Message is one notification for one device.
type Message struct {
	// Title and Body are what the notification shows. Leave both empty for a
	// silent, data-only message the app handles itself (on iOS it is delivered
	// as a background push, which the system may delay or drop).
	Title string
	Body  string
	// Data reaches the app with the notification: a link to open, an id.
	Data map[string]string
	// Collapse replaces an earlier notification with the same key instead of
	// stacking a second one (Android tag, apns-collapse-id). Apple keeps the
	// first 64 bytes.
	Collapse string
	// Group files the notification: the Android channel id and the iOS
	// thread-id. The Android channel must exist in the app.
	Group string
	// TTL is how long Firebase keeps the message for an offline device. At
	// least a minute is sent.
	TTL time.Duration
	// Urgent wakes the device now (Android high priority, APNs priority 10).
	// Android may lower the priority of apps that send urgent messages the user
	// does not open.
	Urgent bool
	// Sound is the iOS sound name; "default" when empty and the message shows
	// something.
	Sound string
}

type request struct {
	ValidateOnly bool        `json:"validate_only,omitempty"`
	Message      wireMessage `json:"message"`
}

type wireMessage struct {
	Token        string            `json:"token"`
	Notification *wireNotification `json:"notification,omitempty"`
	Data         map[string]string `json:"data,omitempty"`
	Android      wireAndroid       `json:"android"`
	APNS         wireAPNS          `json:"apns"`
}

type wireNotification struct {
	Title string `json:"title,omitempty"`
	Body  string `json:"body,omitempty"`
}

type wireAndroid struct {
	Priority     string                   `json:"priority"`
	TTL          string                   `json:"ttl"`
	CollapseKey  string                   `json:"collapse_key,omitempty"`
	Notification *wireAndroidNotification `json:"notification,omitempty"`
}

type wireAndroidNotification struct {
	Tag       string `json:"tag,omitempty"`
	ChannelID string `json:"channel_id,omitempty"`
}

type wireAPNS struct {
	Headers map[string]string `json:"headers"`
	Payload wireAPNSPayload   `json:"payload"`
}

type wireAPNSPayload struct {
	APS wireAPS `json:"aps"`
}

type wireAPS struct {
	ThreadID         string `json:"thread-id,omitempty"`
	Sound            string `json:"sound,omitempty"`
	ContentAvailable int    `json:"content-available,omitempty"`
}

// apnsCollapseMax is the most bytes Apple takes in apns-collapse-id.
const apnsCollapseMax = 64

// BuildRequest is the HTTP v1 body for one message to one device. now is the
// moment of sending: Apple wants the expiry as a clock time. Send builds it
// for you; it is exported so you can log or inspect exactly what is sent.
func BuildRequest(token string, m Message, now time.Time) ([]byte, error) {
	return buildRequest(token, m, now, false)
}

func buildRequest(token string, m Message, now time.Time, validateOnly bool) ([]byte, error) {
	ttl := m.TTL
	if ttl < time.Minute {
		ttl = time.Minute
	}
	visible := m.Title != "" || m.Body != ""
	android := wireAndroid{
		Priority: "NORMAL",
		TTL:      strconv.FormatInt(int64(ttl/time.Second), 10) + "s",
	}
	headers := map[string]string{
		"apns-priority":   "5",
		"apns-expiration": strconv.FormatInt(now.Add(ttl).Unix(), 10),
	}
	aps := wireAPS{ThreadID: m.Group}
	var note *wireNotification
	if visible {
		note = &wireNotification{Title: m.Title, Body: m.Body}
		android.Notification = &wireAndroidNotification{Tag: m.Collapse, ChannelID: m.Group}
		headers["apns-push-type"] = "alert"
		aps.Sound = m.Sound
		if aps.Sound == "" {
			aps.Sound = "default"
		}
		if m.Urgent {
			headers["apns-priority"] = "10"
		}
	} else {
		// A data-only message: Apple accepts it only as a low-priority
		// background push.
		android.CollapseKey = m.Collapse
		headers["apns-push-type"] = "background"
		aps.ContentAvailable = 1
	}
	if m.Urgent {
		android.Priority = "HIGH"
	}
	if m.Collapse != "" {
		id := m.Collapse
		if len(id) > apnsCollapseMax {
			id = id[:apnsCollapseMax]
		}
		headers["apns-collapse-id"] = id
	}
	return json.Marshal(request{ValidateOnly: validateOnly, Message: wireMessage{
		Token:        token,
		Notification: note,
		Data:         m.Data,
		Android:      android,
		APNS:         wireAPNS{Headers: headers, Payload: wireAPNSPayload{APS: aps}},
	}})
}

// Client sends to apps through Firebase. It is safe for concurrent use and
// keeps one access token for as long as Google allows.
type Client struct {
	project string
	sa      ServiceAccount
	base    string
	client  *http.Client
	now     func() time.Time

	mu      sync.Mutex
	access  string
	expires time.Time
}

// Option configures a Client.
type Option func(*Client)

// WithProject sends through another Firebase project than the key file's.
func WithProject(id string) Option { return func(c *Client) { c.project = id } }

// WithBaseURL points the client at another address, such as a test server.
func WithBaseURL(u string) Option {
	return func(c *Client) { c.base = strings.TrimRight(u, "/") }
}

// WithHTTPClient uses another HTTP client. The default has a 10-second timeout
// and follows no redirects.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.client = h } }

// WithClock replaces time.Now.
func WithClock(now func() time.Time) Option { return func(c *Client) { c.now = now } }

// New builds a client for a service account.
func New(sa ServiceAccount, opts ...Option) *Client {
	c := &Client{project: sa.ProjectID, sa: sa, base: DefaultBaseURL, now: time.Now, client: &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Project is the Firebase project messages are sent through.
func (c *Client) Project() string { return c.project }

// token is a cached access token, renewed a minute before it runs out.
func (c *Client) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.access != "" && now.Before(c.expires.Add(-time.Minute)) {
		return c.access, nil
	}
	if c.sa.key == nil {
		return "", errors.New("fcm: the service account has no key; use ParseServiceAccount or LoadServiceAccount")
	}
	assertion, err := c.assertion(now)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.sa.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fcm: access token: %w", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if res.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		return "", fmt.Errorf("fcm: access token refused: %d %s", res.StatusCode, e.Error)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return "", errors.New("fcm: access token: unreadable answer")
	}
	if tok.ExpiresIn <= 0 {
		tok.ExpiresIn = 3600
	}
	c.access, c.expires = tok.AccessToken, now.Add(time.Duration(tok.ExpiresIn)*time.Second)
	return c.access, nil
}

// assertion is the signed JWT a service account trades for an access token.
func (c *Client) assertion(now time.Time) (string, error) {
	header := b64.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"iss": c.sa.ClientEmail, "scope": Scope, "aud": c.sa.TokenURI,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	if err != nil {
		return "", err
	}
	signing := header + "." + b64.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.sa.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64.EncodeToString(sig), nil
}

// Outcome is what Firebase's answer means for the device token.
type Outcome int

const (
	// Delivered: Firebase accepted the message.
	Delivered Outcome = iota
	// Gone: the token is dead, unknown, or belongs to another sender. Delete it.
	Gone
	// Transient: Firebase is busy or unreachable (429, 5xx). Retry later, after
	// Result.RetryAfter when it names a pause.
	Transient
	// Failed: Firebase refused the message itself (too long, a bad field).
	// It is your payload's fault, never a reason to delete the token.
	Failed
	// Unsent: your credentials were refused (the service account, or the APNs
	// key in the Firebase project). The device is fine; fix the configuration.
	Unsent
)

func (o Outcome) String() string {
	switch o {
	case Delivered:
		return "delivered"
	case Gone:
		return "gone"
	case Transient:
		return "transient"
	case Failed:
		return "failed"
	case Unsent:
		return "unsent"
	}
	return "outcome(" + strconv.Itoa(int(o)) + ")"
}

// Result is Firebase's answer.
type Result struct {
	Outcome Outcome
	// StatusCode is the HTTP status, 0 when there was none.
	StatusCode int
	// Code is Firebase's error code ("UNREGISTERED", "QUOTA_EXCEEDED", …).
	Code string
	// RetryAfter is the pause Firebase asked for, 0 when it named none.
	RetryAfter time.Duration
}

type wireError struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
		Details []struct {
			Type      string `json:"@type"`
			ErrorCode string `json:"errorCode"`
		} `json:"details"`
	} `json:"error"`
}

func (e wireError) code() string {
	for _, d := range e.Error.Details {
		if d.ErrorCode != "" {
			return d.ErrorCode
		}
	}
	return e.Error.Status
}

// Send delivers one message to one device. Every outcome but Delivered comes
// with an error that says why.
//
// How Firebase's answers are read:
//
//   - UNREGISTERED or SENDER_ID_MISMATCH: Gone.
//   - INVALID_ARGUMENT about the registration token: Gone. Any other invalid
//     argument is the payload's fault and Failed, so one message that came out
//     too long never deletes every token you have.
//   - 404 NOT_FOUND without detail: Gone (HTTP v1 answers some unregistered
//     tokens that way).
//   - 429 and 5xx: Transient, with Firebase's Retry-After.
//   - 401 and 403 otherwise: Unsent. After a 401 the next call fetches a fresh
//     access token.
func (c *Client) Send(ctx context.Context, token string, m Message) (Result, error) {
	return c.send(ctx, token, m, false)
}

// Validate asks Firebase to check a message to a token without delivering it
// (validate_only). Use it when an app registers a token: Gone means the token
// is no good, before you store it.
func (c *Client) Validate(ctx context.Context, token string, m Message) (Result, error) {
	return c.send(ctx, token, m, true)
}

func (c *Client) send(ctx context.Context, token string, m Message, validateOnly bool) (Result, error) {
	if strings.TrimSpace(token) == "" {
		return Result{Outcome: Gone}, errors.New("fcm: empty device token")
	}
	access, err := c.token(ctx)
	if err != nil {
		return Result{Outcome: Unsent}, err
	}
	body, err := buildRequest(token, m, c.now(), validateOnly)
	if err != nil {
		return Result{Outcome: Failed}, err
	}
	endpoint := c.base + "/v1/projects/" + url.PathEscape(c.project) + "/messages:send"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{Outcome: Failed}, err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	res, err := c.client.Do(req)
	if err != nil {
		return Result{Outcome: Transient}, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 16<<10))
	out := Result{StatusCode: res.StatusCode}
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		out.Outcome = Delivered
		return out, nil
	}
	var e wireError
	_ = json.Unmarshal(raw, &e)
	out.Code = e.code()
	refused := fmt.Errorf("fcm: firebase answered %d %s", res.StatusCode, out.Code)
	switch {
	case out.Code == "UNREGISTERED" || out.Code == "SENDER_ID_MISMATCH":
		out.Outcome = Gone
	case out.Code == "INVALID_ARGUMENT" || res.StatusCode == http.StatusBadRequest:
		if strings.Contains(strings.ToLower(e.Error.Message), "registration token") {
			out.Outcome = Gone
		} else {
			out.Outcome = Failed
		}
	case res.StatusCode == http.StatusNotFound && out.Code == "NOT_FOUND":
		out.Outcome = Gone
	case res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500:
		out.Outcome, out.RetryAfter = Transient, retryAfter(res.Header.Get("Retry-After"))
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
		if res.StatusCode == http.StatusUnauthorized {
			// The cached access token may have been revoked: ask again next time.
			c.mu.Lock()
			c.access = ""
			c.mu.Unlock()
		}
		out.Outcome = Unsent
	default:
		out.Outcome = Failed
	}
	return out, refused
}

// retryAfter reads a Retry-After header in seconds; zero when there is none.
func retryAfter(h string) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 0
}

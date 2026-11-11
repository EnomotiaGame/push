/*
Package webpush sends Web Push messages with the Go standard library and
nothing else.

Two RFCs, no dependency. RFC 8291 encrypts a message for one browser, so the
push service that carries it (Google's, Mozilla's, Apple's, Microsoft's)
carries a sealed envelope and reads nothing. RFC 8292 (VAPID) signs the
request with your server's key, so a push service knows a subscription made
for you is used by you and nobody else. The encryption is tested against the
worked example in RFC 8291 itself, byte for byte.

	keys, _ := webpush.ParseKeys(publicB64, privateB64) // once; see GenerateKeys
	sender, _ := webpush.New(keys, "mailto:ops@example.com")
	sub, _ := webpush.ParseSubscription(browserJSON)    // PushSubscription.toJSON()
	res, err := sender.Send(ctx, sub, []byte(`{"title":"Hello"}`), webpush.Options{TTL: time.Hour})
	if res.Outcome == webpush.Gone {
		// delete the subscription
	}

The endpoint in a subscription is an address the browser hands you, which a
user can forge. The sender posts only to HTTPS addresses on the known push
services (DefaultHosts), so it can never be turned into a relay that POSTs to
your internal network.
*/
package webpush

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var b64 = base64.RawURLEncoding

// decode64 accepts base64url with or without padding, which is how browsers
// and key generators variously write the same bytes.
func decode64(s string) ([]byte, error) {
	return b64.DecodeString(strings.TrimRight(strings.TrimSpace(s), "="))
}

// Keys is the server's VAPID key pair.
type Keys struct {
	// Public is the uncompressed P-256 point, 65 bytes. Browsers are given it
	// as applicationServerKey when they subscribe (see PublicString).
	Public  []byte
	private *ecdsa.PrivateKey
}

// ErrNoKeys is returned by ParseKeys when either key is empty.
var ErrNoKeys = errors.New("webpush: no VAPID keys configured")

// ParseKeys reads a VAPID pair written as base64url: the public point (65
// bytes) and the private scalar (32 bytes). A public key that is not the
// private key's own is refused. A mismatched pair would subscribe browsers
// that every push service then rejects, silently.
func ParseKeys(publicB64, privateB64 string) (Keys, error) {
	if publicB64 == "" || privateB64 == "" {
		return Keys{}, ErrNoKeys
	}
	d, err := decode64(privateB64)
	if err != nil {
		return Keys{}, fmt.Errorf("webpush: private key: %w", err)
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		return Keys{}, fmt.Errorf("webpush: private key: %w", err)
	}
	pub, err := decode64(publicB64)
	if err != nil {
		return Keys{}, fmt.Errorf("webpush: public key: %w", err)
	}
	own, err := priv.PublicKey.Bytes()
	if err != nil {
		return Keys{}, fmt.Errorf("webpush: public key: %w", err)
	}
	if !bytes.Equal(own, pub) {
		return Keys{}, errors.New("webpush: the public key is not the private key's")
	}
	return Keys{Public: pub, private: priv}, nil
}

// GenerateKeys makes a new VAPID pair and returns both halves as base64url.
// Generate once, keep the private half secret, and never rotate it lightly:
// every existing subscription is bound to the public half.
func GenerateKeys() (public, private string, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	pub, err := k.PublicKey.Bytes()
	if err != nil {
		return "", "", err
	}
	d, err := k.Bytes()
	if err != nil {
		return "", "", err
	}
	return b64.EncodeToString(pub), b64.EncodeToString(d), nil
}

// PublicString is the public key as a browser's pushManager.subscribe wants
// it (applicationServerKey).
func (k Keys) PublicString() string { return b64.EncodeToString(k.Public) }

// recordSize is the one record RFC 8188 says a push message is.
const recordSize = 4096

// MaxPayload is the largest plaintext that fits one push message: 4096 bytes,
// less the header (86), the authentication tag (16) and the padding delimiter.
const MaxPayload = recordSize - 86 - 16 - 1

// ErrPayloadTooLarge is a payload over MaxPayload.
var ErrPayloadTooLarge = errors.New("webpush: payload too large")

// encrypt seals a message for one browser (RFC 8291 §3.4). as is a fresh key
// pair per message and salt sixteen fresh bytes; both are parameters so the
// test can feed it the RFC's own.
func encrypt(plaintext, uaPublic, authSecret []byte, as *ecdh.PrivateKey, salt []byte) ([]byte, error) {
	if len(plaintext) > MaxPayload {
		return nil, ErrPayloadTooLarge
	}
	ua, err := ecdh.P256().NewPublicKey(uaPublic)
	if err != nil {
		return nil, fmt.Errorf("webpush: browser key: %w", err)
	}
	shared, err := as.ECDH(ua)
	if err != nil {
		return nil, err
	}
	asPublic := as.PublicKey().Bytes()
	gcm, nonce, err := contentKey(shared, authSecret, uaPublic, asPublic, salt)
	if err != nil {
		return nil, err
	}
	// One record, so it is the last: the padding delimiter is 2 (RFC 8188).
	sealed := gcm.Seal(nil, nonce, append(append([]byte{}, plaintext...), 0x02), nil)

	header := make([]byte, 0, 16+4+1+len(asPublic))
	header = append(header, salt...)
	header = binary.BigEndian.AppendUint32(header, recordSize)
	header = append(header, byte(len(asPublic)))
	header = append(header, asPublic...)
	return append(header, sealed...), nil
}

// contentKey derives the AES-128-GCM key and nonce (RFC 8291 §3.3, §3.4).
func contentKey(shared, authSecret, uaPublic, asPublic, salt []byte) (cipher.AEAD, []byte, error) {
	prkKey, err := hkdf.Extract(sha256.New, shared, authSecret)
	if err != nil {
		return nil, nil, err
	}
	ikm, err := hkdf.Expand(sha256.New, prkKey, "WebPush: info\x00"+string(uaPublic)+string(asPublic), 32)
	if err != nil {
		return nil, nil, err
	}
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil, nil, err
	}
	cek, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return gcm, nonce, nil
}

// Seal encrypts a payload for one browser with a fresh key and salt. p256dh
// and auth are the subscription's keys.
func Seal(plaintext, p256dh, auth []byte) ([]byte, error) {
	as, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return encrypt(plaintext, p256dh, auth, as, salt)
}

// Open is the browser's half of RFC 8291: it unseals a message with the
// browser's own key. A server never needs it; tests do, to read what a
// browser would have been shown.
func Open(body []byte, ua *ecdh.PrivateKey, auth []byte) ([]byte, error) {
	if len(body) < 21 {
		return nil, errors.New("webpush: short message")
	}
	salt, idlen := body[:16], int(body[20])
	if len(body) < 21+idlen {
		return nil, errors.New("webpush: short message")
	}
	asPublic, sealed := body[21:21+idlen], body[21+idlen:]
	as, err := ecdh.P256().NewPublicKey(asPublic)
	if err != nil {
		return nil, err
	}
	shared, err := ua.ECDH(as)
	if err != nil {
		return nil, err
	}
	gcm, nonce, err := contentKey(shared, auth, ua.PublicKey().Bytes(), asPublic, salt)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, err
	}
	// Strip the padding delimiter and whatever padding follows it.
	end := bytes.LastIndexByte(plain, 0x02)
	if end < 0 {
		return nil, errors.New("webpush: no padding delimiter")
	}
	return plain[:end], nil
}

// vapid is the Authorization header for one push service (RFC 8292 §2): a JWT
// naming the service's origin, valid for twelve hours, and who to contact.
func (k Keys) vapid(endpoint *url.URL, subject string, now time.Time) (string, error) {
	if k.private == nil {
		return "", ErrNoKeys
	}
	head := b64.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`))
	claims, err := json.Marshal(map[string]any{
		"aud": endpoint.Scheme + "://" + endpoint.Host,
		"exp": now.Add(12 * time.Hour).Unix(),
		"sub": subject,
	})
	if err != nil {
		return "", err
	}
	unsigned := head + "." + b64.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	r, s, err := ecdsa.Sign(rand.Reader, k.private, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return "vapid t=" + unsigned + "." + b64.EncodeToString(sig) + ", k=" + k.PublicString(), nil
}

// DefaultHosts are the push services browsers use. An entry starting with a
// dot admits any subdomain.
var DefaultHosts = []string{
	"fcm.googleapis.com",                // Chrome, Edge on Android, Opera, Samsung Internet
	"updates.push.services.mozilla.com", // Firefox
	".push.services.mozilla.com",
	"web.push.apple.com",  // Safari, and iOS web apps on the home screen
	".notify.windows.com", // Edge on Windows
}

// ErrEndpoint is an endpoint that is not HTTPS on a known push service.
var ErrEndpoint = errors.New("webpush: not a push service address")

// CheckEndpoint parses an endpoint and admits it only if it is HTTPS on one of
// DefaultHosts, with no port and no user info. Check it when a browser
// registers a subscription, so a forged one is refused before it is stored.
func CheckEndpoint(raw string) (*url.URL, error) { return checkEndpoint(raw, DefaultHosts) }

func checkEndpoint(raw string, hosts []string) (*url.URL, error) {
	if len(raw) > 1024 {
		return nil, ErrEndpoint
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return nil, ErrEndpoint
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range hosts {
		if strings.HasPrefix(h, ".") {
			if strings.HasSuffix(host, h) {
				return u, nil
			}
		} else if host == h {
			return u, nil
		}
	}
	return nil, ErrEndpoint
}

// Subscription is one browser, as it described itself.
type Subscription struct {
	Endpoint string
	// P256dh is the browser's public key, 65 bytes.
	P256dh []byte
	// Auth is the browser's authentication secret, 16 bytes.
	Auth []byte
}

// ParseSubscription reads what a browser's PushSubscription.toJSON() gives:
//
//	{"endpoint":"https://…","keys":{"p256dh":"…","auth":"…"}}
//
// It checks the endpoint (CheckEndpoint) and the keys' shape.
func ParseSubscription(raw []byte) (Subscription, error) {
	var in struct {
		Endpoint string `json:"endpoint"`
		Keys     struct {
			P256dh string `json:"p256dh"`
			Auth   string `json:"auth"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return Subscription{}, errors.New("webpush: subscription is not JSON")
	}
	if _, err := CheckEndpoint(in.Endpoint); err != nil {
		return Subscription{}, err
	}
	p256dh, err := decode64(in.Keys.P256dh)
	if err != nil {
		return Subscription{}, errors.New("webpush: subscription p256dh is not base64url")
	}
	if _, err := ecdh.P256().NewPublicKey(p256dh); err != nil {
		return Subscription{}, errors.New("webpush: subscription p256dh is not a P-256 point")
	}
	auth, err := decode64(in.Keys.Auth)
	if err != nil || len(auth) != 16 {
		return Subscription{}, errors.New("webpush: subscription auth is not 16 bytes of base64url")
	}
	return Subscription{Endpoint: in.Endpoint, P256dh: p256dh, Auth: auth}, nil
}

// Urgency tells a push service how soon a device should wake for the message
// (RFC 8030 §5.3). Lower urgencies save battery.
type Urgency string

const (
	VeryLow Urgency = "very-low"
	Low     Urgency = "low"
	Normal  Urgency = "normal"
	High    Urgency = "high"
)

// Options says how one message travels.
type Options struct {
	// TTL is how long the push service may hold the message for an offline
	// browser. Zero means deliver now or never.
	TTL time.Duration
	// Urgency is Normal when empty.
	Urgency Urgency
	// Topic replaces an undelivered message with the same topic instead of
	// queueing a second one (RFC 8030 §5.4): at most 32 characters of the
	// base64url alphabet.
	Topic string
}

// Outcome is what a push service's answer means for the subscription.
type Outcome int

const (
	// Delivered: the push service accepted the message.
	Delivered Outcome = iota
	// Gone: the browser unsubscribed, the subscription expired, or it was never
	// valid. Delete it; sending again will never work.
	Gone
	// Transient: the service asked you to come back (429, 5xx) or could not be
	// reached. Retry later, after Result.RetryAfter when it says.
	Transient
	// Failed: anything else. Count it, and let a subscription that keeps
	// failing go.
	Failed
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
	}
	return "outcome(" + strconv.Itoa(int(o)) + ")"
}

// Result is a push service's answer.
type Result struct {
	Outcome Outcome
	// StatusCode is the HTTP status, 0 when there was none.
	StatusCode int
	// RetryAfter is the pause the service asked for, 0 when it named none.
	RetryAfter time.Duration
}

// Sender delivers sealed messages.
type Sender struct {
	keys    Keys
	subject string
	hosts   []string
	client  *http.Client
	now     func() time.Time
}

// Option configures a Sender.
type Option func(*Sender)

// WithHTTPClient uses another HTTP client. The default has a 10-second timeout
// and follows no redirects: a push service answers where it was asked.
func WithHTTPClient(c *http.Client) Option { return func(s *Sender) { s.client = c } }

// WithHosts replaces DefaultHosts, for a self-hosted push service or a test.
func WithHosts(hosts ...string) Option { return func(s *Sender) { s.hosts = hosts } }

// WithClock replaces time.Now for the VAPID token's expiry.
func WithClock(now func() time.Time) Option { return func(s *Sender) { s.now = now } }

// New builds a sender. subject is how a push service can reach you about your
// traffic: a "mailto:" or "https:" URL (RFC 8292 §2.1). Apple refuses a
// mailto: subject on localhost, so use your real address.
func New(keys Keys, subject string, opts ...Option) (*Sender, error) {
	if keys.private == nil {
		return nil, ErrNoKeys
	}
	if !strings.HasPrefix(subject, "mailto:") && !strings.HasPrefix(subject, "https://") {
		return nil, errors.New(`webpush: subject must be a "mailto:" or "https://" URL`)
	}
	s := &Sender{keys: keys, subject: subject, hosts: DefaultHosts, now: time.Now, client: &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

var topicChars = func() [256]bool {
	var ok [256]bool
	for _, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" {
		ok[c] = true
	}
	return ok
}()

func validTopic(t string) bool {
	if len(t) > 32 {
		return false
	}
	for i := 0; i < len(t); i++ {
		if !topicChars[t[i]] {
			return false
		}
	}
	return true
}

// Send delivers one payload to one browser. The payload is what your service
// worker's push event receives (event.data); JSON is the usual choice.
//
// An error comes with every outcome but Delivered and says why. An endpoint
// that is not a push service, or browser keys that are not a valid point, are
// Gone: no retry will make them work.
func (s *Sender) Send(ctx context.Context, sub Subscription, payload []byte, o Options) (Result, error) {
	u, err := checkEndpoint(sub.Endpoint, s.hosts)
	if err != nil {
		return Result{Outcome: Gone}, err
	}
	if o.Topic != "" && !validTopic(o.Topic) {
		return Result{Outcome: Failed}, errors.New("webpush: topic must be at most 32 base64url characters")
	}
	if len(payload) > MaxPayload {
		return Result{Outcome: Failed}, ErrPayloadTooLarge
	}
	body, err := Seal(payload, sub.P256dh, sub.Auth)
	if err != nil {
		return Result{Outcome: Gone}, err
	}
	auth, err := s.keys.vapid(u, s.subject, s.now())
	if err != nil {
		return Result{Outcome: Failed}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return Result{Outcome: Failed}, err
	}
	urgency := o.Urgency
	if urgency == "" {
		urgency = Normal
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("TTL", strconv.Itoa(int(o.TTL/time.Second)))
	req.Header.Set("Urgency", string(urgency))
	if o.Topic != "" {
		req.Header.Set("Topic", o.Topic)
	}
	res, err := s.client.Do(req)
	if err != nil {
		return Result{Outcome: Transient}, err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	out := Result{StatusCode: res.StatusCode}
	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
		out.Outcome = Delivered
		return out, nil
	case res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusGone:
		out.Outcome = Gone
		return out, fmt.Errorf("webpush: subscription gone (%d)", res.StatusCode)
	case res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500:
		out.Outcome, out.RetryAfter = Transient, retryAfter(res.Header.Get("Retry-After"))
		return out, fmt.Errorf("webpush: push service answered %d", res.StatusCode)
	default:
		out.Outcome = Failed
		return out, fmt.Errorf("webpush: push service answered %d", res.StatusCode)
	}
}

// retryAfter reads a Retry-After header in seconds; zero when there is none.
func retryAfter(h string) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 0
}

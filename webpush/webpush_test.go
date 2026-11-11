package webpush

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := decode64(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}

// The RFC's own example, byte for byte (RFC 8291 §5). If this passes, every
// browser can open what this package seals; if it does not, none can.
func TestEncryptionMatchesTheRFCExample(t *testing.T) {
	as, err := ecdh.P256().NewPrivateKey(mustB64(t, "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := encrypt(
		[]byte("When I grow up, I want to be a watermelon"),
		mustB64(t, "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"),
		mustB64(t, "BTBZMqHH6r4Tts7J_aSIgg"),
		as,
		mustB64(t, "DGv6ra1nlYgDCS1FRnbzlw"),
	)
	if err != nil {
		t.Fatal(err)
	}
	want := "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
	if b64.EncodeToString(got) != want {
		t.Fatalf("sealed message differs from RFC 8291:\n got %s\nwant %s", b64.EncodeToString(got), want)
	}
}

func TestAGeneratedPairParsesAndAMismatchedOneDoesNot(t *testing.T) {
	pub, priv, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseKeys(pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Public) != 65 || k.PublicString() != pub {
		t.Fatalf("public key %d bytes", len(k.Public))
	}
	if _, err := ParseKeys(pub+"==", priv); err != nil {
		t.Fatalf("padded base64 refused: %v", err)
	}
	other, _, _ := GenerateKeys()
	if _, err := ParseKeys(other, priv); err == nil {
		t.Fatal("a public key from another pair was accepted")
	}
	if _, err := ParseKeys("", ""); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("no keys: %v", err)
	}
}

// Only push services. The endpoint is a browser's word, so anything that is
// not HTTPS on a known push service is refused; otherwise the sender is an
// open POST relay into your network.
func TestOnlyPushServicesAreEndpoints(t *testing.T) {
	for _, ok := range []string{
		"https://fcm.googleapis.com/fcm/send/abc:def",
		"https://updates.push.services.mozilla.com/wpush/v2/gAAA",
		"https://web.push.apple.com/QGx",
		"https://wns2-par02p.notify.windows.com/w/?token=x",
	} {
		if _, err := CheckEndpoint(ok); err != nil {
			t.Errorf("%s refused", ok)
		}
	}
	for _, bad := range []string{
		"http://fcm.googleapis.com/fcm/send/abc",
		"https://fcm.googleapis.com.evil.example/x",
		"https://evilfcm.googleapis.com/x",
		"https://127.0.0.1/x",
		"https://localhost/x",
		"https://169.254.169.254/latest/meta-data",
		"https://fcm.googleapis.com:8443/x",
		"https://user@fcm.googleapis.com/x",
		"https://notify.windows.com.evil/x",
		"javascript:alert(1)",
		"https://fcm.googleapis.com/" + strings.Repeat("a", 1024),
	} {
		if _, err := CheckEndpoint(bad); err == nil {
			t.Errorf("%.60s admitted", bad)
		}
	}
}

func TestASealedMessageOpensForItsBrowserOnly(t *testing.T) {
	ua, _ := ecdh.P256().GenerateKey(rand.Reader)
	secret := []byte("0123456789abcdef")
	body, err := Seal([]byte(`{"title":"Hello"}`), ua.PublicKey().Bytes(), secret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(body, ua, secret)
	if err != nil || string(got) != `{"title":"Hello"}` {
		t.Fatalf("%q %v", got, err)
	}
	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, err := Open(body, other, secret); err == nil {
		t.Fatal("another browser opened it")
	}
}

func TestThePayloadLimitIsTheRFCs(t *testing.T) {
	ua, _ := ecdh.P256().GenerateKey(rand.Reader)
	secret := []byte("0123456789abcdef")
	body, err := Seal(make([]byte, MaxPayload), ua.PublicKey().Bytes(), secret)
	if err != nil || len(body) != recordSize {
		t.Fatalf("the largest payload: %d bytes, %v", len(body), err)
	}
	if _, err := Seal(make([]byte, MaxPayload+1), ua.PublicKey().Bytes(), secret); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("one byte over: %v", err)
	}
}

func subscriptionJSON(t *testing.T, ua *ecdh.PrivateKey, endpoint string) []byte {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{
		"endpoint": endpoint, "expirationTime": nil,
		"keys": map[string]string{"p256dh": b64.EncodeToString(ua.PublicKey().Bytes()), "auth": "BTBZMqHH6r4Tts7J_aSIgg"},
	})
	return raw
}

func TestASubscriptionIsReadAsTheBrowserWritesIt(t *testing.T) {
	ua, _ := ecdh.P256().GenerateKey(rand.Reader)
	sub, err := ParseSubscription(subscriptionJSON(t, ua, "https://fcm.googleapis.com/fcm/send/abc"))
	if err != nil || len(sub.P256dh) != 65 || len(sub.Auth) != 16 {
		t.Fatalf("%+v %v", sub, err)
	}
	for name, raw := range map[string]string{
		"not json":     `endpoint`,
		"bad endpoint": string(subscriptionJSON(t, ua, "https://example.com/x")),
		"bad point":    `{"endpoint":"https://fcm.googleapis.com/x","keys":{"p256dh":"AAAA","auth":"BTBZMqHH6r4Tts7J_aSIgg"}}`,
		"short auth":   `{"endpoint":"https://fcm.googleapis.com/x","keys":{"p256dh":"` + b64.EncodeToString(ua.PublicKey().Bytes()) + `","auth":"AAAA"}}`,
	} {
		if _, err := ParseSubscription([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestASenderNeedsKeysAndAContact(t *testing.T) {
	pub, priv, _ := GenerateKeys()
	k, _ := ParseKeys(pub, priv)
	if _, err := New(Keys{}, "mailto:ops@example.com"); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("no keys: %v", err)
	}
	for _, bad := range []string{"", "ops@example.com", "http://example.com"} {
		if _, err := New(k, bad); err == nil {
			t.Errorf("subject %q accepted", bad)
		}
	}
}

// pushService stands where a browser's push service would: it checks the
// VAPID signature with the sender's public key, opens the message with the
// browser's key, and answers what the test says.
type pushService struct {
	t      *testing.T
	vapid  *ecdsa.PublicKey
	ua     *ecdh.PrivateKey
	auth   []byte
	status int
	header http.Header
	got    []byte
	sent   http.Header
}

func (p *pushService) RoundTrip(r *http.Request) (*http.Response, error) {
	p.sent = r.Header.Clone()
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(strings.SplitN(auth, ",", 2)[0], "vapid t=")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		p.t.Fatalf("authorization %q", auth)
	}
	sig, _ := b64.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(p.vapid, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		p.t.Fatal("the VAPID signature does not verify")
	}
	claims, _ := b64.DecodeString(parts[1])
	var c map[string]any
	_ = json.Unmarshal(claims, &c)
	if c["aud"] != "https://fcm.googleapis.com" || c["sub"] != "mailto:ops@example.com" {
		p.t.Fatalf("claims %v", c)
	}
	body, _ := io.ReadAll(r.Body)
	got, err := Open(body, p.ua, p.auth)
	if err != nil {
		p.t.Fatalf("the browser could not open the message: %v", err)
	}
	p.got = got
	rec := httptest.NewRecorder()
	for k, v := range p.header {
		rec.Header()[k] = v
	}
	rec.WriteHeader(p.status)
	return rec.Result(), nil
}

func TestSendSealsSignsAndReadsTheAnswer(t *testing.T) {
	pub, priv, _ := GenerateKeys()
	keys, _ := ParseKeys(pub, priv)
	ua, _ := ecdh.P256().GenerateKey(rand.Reader)
	sub, _ := ParseSubscription(subscriptionJSON(t, ua, "https://fcm.googleapis.com/fcm/send/abc"))
	x, y := elliptic.Unmarshal(elliptic.P256(), keys.Public) //nolint:staticcheck // a test reading a known point
	svc := &pushService{t: t, vapid: &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, ua: ua, auth: sub.Auth}
	s, err := New(keys, "mailto:ops@example.com", WithHTTPClient(&http.Client{Transport: svc}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, tc := range []struct {
		status int
		retry  string
		want   Outcome
		wait   time.Duration
	}{
		{201, "", Delivered, 0},
		{410, "", Gone, 0},
		{404, "", Gone, 0},
		{429, "5", Transient, 5 * time.Second},
		{503, "", Transient, 0},
		{400, "", Failed, 0},
		{403, "", Failed, 0},
	} {
		svc.status, svc.header = tc.status, http.Header{}
		if tc.retry != "" {
			svc.header.Set("Retry-After", tc.retry)
		}
		res, err := s.Send(ctx, sub, []byte(`{"title":"Hi"}`), Options{TTL: time.Hour, Urgency: High, Topic: "order-42"})
		if res.Outcome != tc.want || res.RetryAfter != tc.wait || res.StatusCode != tc.status || (err == nil) != (tc.want == Delivered) {
			t.Errorf("%d: %+v %v, want %v (wait %v)", tc.status, res, err, tc.want, tc.wait)
		}
	}
	if string(svc.got) != `{"title":"Hi"}` {
		t.Fatalf("the browser read %q", svc.got)
	}
	for k, want := range map[string]string{"TTL": "3600", "Urgency": "high", "Topic": "order-42", "Content-Encoding": "aes128gcm"} {
		if got := svc.sent.Get(k); got != want {
			t.Errorf("%s: %q, want %q", k, got, want)
		}
	}
	svc.status = 201
	if _, err := s.Send(ctx, sub, []byte(`{}`), Options{}); err != nil || svc.sent.Get("Urgency") != "normal" || svc.sent.Get("TTL") != "0" {
		t.Fatalf("defaults: %v, urgency %q ttl %q", err, svc.sent.Get("Urgency"), svc.sent.Get("TTL"))
	}
}

func TestSendRefusesWhatCanNeverWork(t *testing.T) {
	pub, priv, _ := GenerateKeys()
	keys, _ := ParseKeys(pub, priv)
	called := false
	s, _ := New(keys, "mailto:ops@example.com", WithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("unreachable")
	})}))
	ua, _ := ecdh.P256().GenerateKey(rand.Reader)
	good := Subscription{Endpoint: "https://fcm.googleapis.com/x", P256dh: ua.PublicKey().Bytes(), Auth: make([]byte, 16)}
	ctx := context.Background()

	forged := good
	forged.Endpoint = "https://10.0.0.1/admin"
	if res, err := s.Send(ctx, forged, []byte(`{}`), Options{}); res.Outcome != Gone || !errors.Is(err, ErrEndpoint) {
		t.Errorf("a forged endpoint: %+v %v", res, err)
	}
	broken := good
	broken.P256dh = []byte{4, 1, 2}
	if res, _ := s.Send(ctx, broken, []byte(`{}`), Options{}); res.Outcome != Gone {
		t.Errorf("a broken browser key: %+v", res)
	}
	if res, err := s.Send(ctx, good, make([]byte, MaxPayload+1), Options{}); res.Outcome != Failed || !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("a payload too large: %+v %v", res, err)
	}
	if res, _ := s.Send(ctx, good, []byte(`{}`), Options{Topic: "not a topic!"}); res.Outcome != Failed {
		t.Errorf("a bad topic: %+v", res)
	}
	if called {
		t.Fatal("a request was sent for a message that could never work")
	}
	if res, _ := s.Send(ctx, good, []byte(`{}`), Options{}); res.Outcome != Transient || !called {
		t.Errorf("an unreachable service: %+v", res)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTheVAPIDHeaderNamesTheServicesOrigin(t *testing.T) {
	pub, priv, _ := GenerateKeys()
	k, _ := ParseKeys(pub, priv)
	u, _ := url.Parse("https://web.push.apple.com/QGx/abc")
	h, err := k.vapid(u, "https://example.com/contact", time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "vapid t=") || !strings.HasSuffix(h, ", k="+pub) {
		t.Fatalf("header %q", h)
	}
	claims, _ := b64.DecodeString(strings.Split(strings.TrimPrefix(h, "vapid t="), ".")[1])
	var c struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
	}
	_ = json.Unmarshal(claims, &c)
	if c.Aud != "https://web.push.apple.com" || c.Exp != 1_800_000_000+12*3600 {
		t.Fatalf("claims %+v", c)
	}
}

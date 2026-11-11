package fcm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeFirebase stands where Google's token endpoint and Firebase would. It
// verifies the signed JWT with the key's public half, as Google does, and
// answers a message by its token.
type fakeFirebase struct {
	srv    *httptest.Server
	pub    *rsa.PublicKey
	mu     sync.Mutex
	tokens int
	bodies []request
}

func newFakeFirebase(t *testing.T, key *rsa.PrivateKey) *fakeFirebase {
	t.Helper()
	f := &fakeFirebase{pub: &key.PublicKey}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeFirebase) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/token":
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
			return
		}
		parts := strings.Split(r.Form.Get("assertion"), ".")
		if len(parts) != 3 {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		sig, _ := b64.DecodeString(parts[2])
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if rsa.VerifyPKCS1v15(f.pub, crypto.SHA256, sum[:], sig) != nil {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		raw, _ := b64.DecodeString(parts[1])
		var claims map[string]any
		_ = json.Unmarshal(raw, &claims)
		if claims["scope"] != Scope || claims["aud"] != f.srv.URL+"/token" || claims["iss"] != "sender@proj.iam.gserviceaccount.com" {
			http.Error(w, `{"error":"invalid_scope"}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.tokens++
		n := f.tokens
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-" + strconv.Itoa(n), "expires_in": 3600, "token_type": "Bearer"})
	case "/v1/projects/proj/messages:send":
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer at-") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req request
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.bodies = append(f.bodies, req)
		f.mu.Unlock()
		refuse := func(status int, s, code, msg string) {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"error":{"code":`+strconv.Itoa(status)+`,"message":"`+msg+`","status":"`+s+
				`","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"`+code+`"}]}}`)
		}
		switch req.Message.Token {
		case "dead":
			refuse(404, "NOT_FOUND", "UNREGISTERED", "Requested entity was not found.")
		case "notatoken":
			refuse(400, "INVALID_ARGUMENT", "INVALID_ARGUMENT", "The registration token is not a valid FCM registration token")
		case "badpayload":
			refuse(400, "INVALID_ARGUMENT", "INVALID_ARGUMENT", "Invalid value at 'message.android.ttl'")
		case "mismatch":
			refuse(403, "PERMISSION_DENIED", "SENDER_ID_MISMATCH", "SenderId mismatch")
		case "busy":
			w.Header().Set("Retry-After", "7")
			refuse(503, "UNAVAILABLE", "UNAVAILABLE", "The service is currently unavailable.")
		case "quota":
			refuse(429, "RESOURCE_EXHAUSTED", "QUOTA_EXCEEDED", "Quota exceeded.")
		case "apns":
			refuse(401, "UNAUTHENTICATED", "THIRD_PARTY_AUTH_ERROR", "Auth error from APNS or Web Push Service")
		default:
			_, _ = io.WriteString(w, `{"name":"projects/proj/messages/1"}`)
		}
	default:
		http.NotFound(w, r)
	}
}

func serviceAccountJSON(t *testing.T, key *rsa.PrivateKey, tokenURI string) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{
		"type": "service_account", "project_id": "proj", "private_key_id": "k1",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": "sender@proj.iam.gserviceaccount.com", "token_uri": tokenURI,
	})
	return raw
}

// What Firebase says, and what it means for the token. A dead token is Gone;
// a payload Firebase did not like is the sender's mistake and Failed, never a
// reason to delete a device; a bad minute is Transient with Firebase's own
// pause; refused credentials are Unsent.
func TestTheClientReadsFirebasesAnswers(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fb := newFakeFirebase(t, key)
	sa, err := ParseServiceAccount(serviceAccountJSON(t, key, fb.srv.URL+"/token"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c := New(sa, WithBaseURL(fb.srv.URL), WithHTTPClient(fb.srv.Client()), WithClock(func() time.Time { return now }))
	if c.Project() != "proj" {
		t.Fatalf("project %q, want the key file's", c.Project())
	}
	ctx := context.Background()
	m := Message{Title: "Your order shipped", Body: "It arrives on Friday.", Data: map[string]string{"url": "/orders/42"}}
	for _, tc := range []struct {
		token string
		want  Outcome
		code  string
		wait  time.Duration
	}{
		{"good-1", Delivered, "", 0},
		{"good-2", Delivered, "", 0},
		{"dead", Gone, "UNREGISTERED", 0},
		{"notatoken", Gone, "INVALID_ARGUMENT", 0},
		{"mismatch", Gone, "SENDER_ID_MISMATCH", 0},
		{"badpayload", Failed, "INVALID_ARGUMENT", 0},
		{"busy", Transient, "UNAVAILABLE", 7 * time.Second},
		{"quota", Transient, "QUOTA_EXCEEDED", 0},
	} {
		res, err := c.Send(ctx, tc.token, m)
		if res.Outcome != tc.want || res.RetryAfter != tc.wait || res.Code != tc.code || (err == nil) != (tc.want == Delivered) {
			t.Errorf("%s: %+v (err %v), want %v %s (wait %v)", tc.token, res, err, tc.want, tc.code, tc.wait)
		}
	}
	// One access token for an hour, not one per message.
	if fb.tokens != 1 {
		t.Fatalf("%d access tokens for eight messages", fb.tokens)
	}
	if n := fb.bodies[0].Message.Notification; n == nil || n.Title != "Your order shipped" {
		t.Fatalf("Firebase read %+v", fb.bodies[0].Message)
	}
	// Refused credentials are not the device's fault, and the next message
	// asks for a fresh token.
	if res, err := c.Send(ctx, "apns", m); res.Outcome != Unsent || err == nil {
		t.Fatalf("an APNs auth error: %+v %v", res, err)
	}
	if res, _ := c.Send(ctx, "good-3", m); res.Outcome != Delivered || fb.tokens != 2 {
		t.Fatalf("after a 401: %+v, %d tokens", res, fb.tokens)
	}
	// An hour later the token is renewed.
	now = now.Add(time.Hour)
	if res, _ := c.Send(ctx, "good-4", m); res.Outcome != Delivered || fb.tokens != 3 {
		t.Fatalf("an hour on: %+v, %d tokens", res, fb.tokens)
	}
	// Validate asks without delivering.
	if res, err := c.Validate(ctx, "good-5", m); res.Outcome != Delivered || err != nil || !fb.bodies[len(fb.bodies)-1].ValidateOnly {
		t.Fatalf("validate: %+v %v", res, err)
	}
	if res, _ := c.Send(ctx, "  ", m); res.Outcome != Gone {
		t.Fatalf("an empty token: %+v", res)
	}

	// A key Google does not know: no token, nothing sent.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrong, _ := ParseServiceAccount(serviceAccountJSON(t, other, fb.srv.URL+"/token"))
	if res, err := New(wrong, WithBaseURL(fb.srv.URL), WithHTTPClient(fb.srv.Client())).Send(ctx, "good-6", m); res.Outcome != Unsent || err == nil {
		t.Fatalf("a wrong key: %+v %v", res, err)
	}
	if res, _ := New(ServiceAccount{ProjectID: "proj"}).Send(ctx, "good-7", m); res.Outcome != Unsent {
		t.Fatalf("an unparsed service account: %+v", res)
	}
}

// Many goroutines share one access token.
func TestConcurrentSendsShareOneToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	fb := newFakeFirebase(t, key)
	sa, _ := ParseServiceAccount(serviceAccountJSON(t, key, fb.srv.URL+"/token"))
	c := New(sa, WithBaseURL(fb.srv.URL), WithHTTPClient(fb.srv.Client()))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if res, err := c.Send(context.Background(), "good-"+strconv.Itoa(i), Message{Title: "x"}); res.Outcome != Delivered {
				t.Errorf("%d: %+v %v", i, res, err)
			}
		}(i)
	}
	wg.Wait()
	if fb.tokens != 1 {
		t.Fatalf("%d access tokens for twenty concurrent sends", fb.tokens)
	}
}

func TestTheServiceAccountIsReadOrRefused(t *testing.T) {
	if _, err := LoadServiceAccount(""); !errors.Is(err, ErrNoServiceAccount) {
		t.Fatalf("no path: %v", err)
	}
	dir := t.TempDir()
	if _, err := LoadServiceAccount(filepath.Join(dir, "missing.json")); err == nil || errors.Is(err, ErrNoServiceAccount) {
		t.Fatalf("a missing file: %v", err)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, raw := range map[string]string{
		"not json":   "-----BEGIN PRIVATE KEY-----",
		"no key":     `{"type":"service_account","client_email":"a@b"}`,
		"wrong type": `{"type":"authorized_user","client_email":"a@b","private_key":"x"}`,
		"not pem":    `{"type":"service_account","client_email":"a@b","private_key":"secret-material"}`,
	} {
		_, err := ParseServiceAccount([]byte(raw))
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "secret-material") {
			t.Errorf("%s: the error repeats the file: %v", name, err)
		}
	}
	path := filepath.Join(dir, "sa.json")
	if err := os.WriteFile(path, serviceAccountJSON(t, key, ""), 0o600); err != nil {
		t.Fatal(err)
	}
	sa, err := LoadServiceAccount(path)
	if err != nil || sa.ProjectID != "proj" || sa.TokenURI != DefaultTokenURL || sa.key == nil || sa.PrivateKey != "" {
		t.Fatalf("a good file: %+v %v", sa, err)
	}
	// A PKCS#1 key, as older tools write it, reads too.
	der := x509.MarshalPKCS1PrivateKey(key)
	raw, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "a@b",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))})
	if _, err := ParseServiceAccount(raw); err != nil {
		t.Fatalf("a PKCS#1 key: %v", err)
	}
}

func decode(t *testing.T, raw []byte) request {
	t.Helper()
	var r request
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// A visible notification: a sound, the group on both platforms, the collapse
// key cut to Apple's limit, and urgency on both platforms.
func TestAVisibleNotificationTravelsAsAnAlert(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	raw, err := BuildRequest("tok", Message{
		Title: "Hello", Body: "World", Data: map[string]string{"url": "/x"},
		Collapse: strings.Repeat("c", 80), Group: "orders", TTL: 2 * time.Hour, Urgent: true,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, raw).Message
	if m.Notification == nil || m.Notification.Title != "Hello" || m.Data["url"] != "/x" {
		t.Fatalf("message %+v", m)
	}
	if m.Android.Priority != "HIGH" || m.Android.TTL != "7200s" || m.Android.Notification == nil ||
		m.Android.Notification.ChannelID != "orders" || len(m.Android.Notification.Tag) != 80 {
		t.Fatalf("android %+v %+v", m.Android, m.Android.Notification)
	}
	h := m.APNS.Headers
	if h["apns-push-type"] != "alert" || h["apns-priority"] != "10" || len(h["apns-collapse-id"]) != 64 ||
		h["apns-expiration"] != strconv.FormatInt(now.Add(2*time.Hour).Unix(), 10) {
		t.Fatalf("apns headers %v", h)
	}
	if m.APNS.Payload.APS.Sound != "default" || m.APNS.Payload.APS.ThreadID != "orders" || m.APNS.Payload.APS.ContentAvailable != 0 {
		t.Fatalf("aps %+v", m.APNS.Payload.APS)
	}
}

// A data-only message has no notification, and travels to Apple as a
// background push at the priority Apple allows.
func TestADataOnlyMessageIsSilent(t *testing.T) {
	raw, _ := BuildRequest("tok", Message{Data: map[string]string{"sync": "1"}, Collapse: "sync", Urgent: true}, time.Unix(0, 0))
	m := decode(t, raw).Message
	if m.Notification != nil || m.Android.Notification != nil || m.Android.CollapseKey != "sync" || m.Android.Priority != "HIGH" {
		t.Fatalf("message %+v", m)
	}
	h := m.APNS.Headers
	if h["apns-push-type"] != "background" || h["apns-priority"] != "5" || m.APNS.Payload.APS.ContentAvailable != 1 || m.APNS.Payload.APS.Sound != "" {
		t.Fatalf("apns %v %+v", h, m.APNS.Payload.APS)
	}
	if !strings.Contains(string(raw), `"ttl":"60s"`) {
		t.Fatalf("a TTL under a minute is not raised to one: %s", raw)
	}
}

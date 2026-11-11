# push

[![Go Reference](https://pkg.go.dev/badge/github.com/EnomotiaGame/push.svg)](https://pkg.go.dev/github.com/EnomotiaGame/push)
[![CI](https://github.com/EnomotiaGame/push/actions/workflows/ci.yml/badge.svg)](https://github.com/EnomotiaGame/push/actions/workflows/ci.yml)

Push notifications from Go to browsers and to Android and iOS apps, with the standard library and nothing else.

> **From the ENOMOTIA team.** We build [ENOMOTIA](https://enomotia.net), a strategy game set in ancient Greece that you play in the browser and on your phone. Along the way we keep meeting problems that every web and mobile product meets sooner or later. When one of our fixes turns out to be useful beyond the game, we clean it up and publish it here so you don't have to solve it again. Issues, ideas and pull requests are welcome: see [CONTRIBUTING](https://github.com/EnomotiaGame/.github/blob/main/CONTRIBUTING.md).

The game tells players when their army arrives, when a building finishes and when someone attacks, in the browser and in the app. We didn't want a large dependency on the path of every one of those messages. The two protocols turned out to be small enough to write against the RFCs directly:

| Package | Sends to | How |
|---|---|---|
| [`webpush`](https://pkg.go.dev/github.com/EnomotiaGame/push/webpush) | Chrome, Firefox, Safari, Edge, and iOS web apps on the home screen | RFC 8291 encryption, RFC 8292 (VAPID) signing, RFC 8030 delivery |
| [`fcm`](https://pkg.go.dev/github.com/EnomotiaGame/push/fcm) | Android and iOS apps through Firebase Cloud Messaging | HTTP v1 API, service-account JWT (RFC 7523), cached access token |

Both have **zero dependencies** and need Go 1.25 or later.

## What you get

- **Verified encryption.** `webpush` is tested against the worked example in RFC 8291, byte for byte.
- **An answer you can act on.** Every send returns an `Outcome`, not just an error:
  - `Delivered`
  - `Gone`: delete the subscription or token
  - `Transient`: retry, with the service's `Retry-After`
  - `Failed`: your payload's fault, so keep the token
  - `Unsent` (FCM only): your credentials were refused, the device is fine

  One malformed message never wipes your device table.
- **No SSRF.** A Web Push endpoint is an address a browser hands you, and a user can forge it. The sender only posts to HTTPS addresses on the real push services, so it can't be turned into a relay into your internal network. Check endpoints with `CheckEndpoint` when you store them, too.
- **Real-world details handled.** Things that cost us a debugging session each:
  - a VAPID public key that does not match the private one is refused at start-up;
  - padded or unpadded base64 is accepted;
  - Apple's 64-byte `apns-collapse-id` limit is respected;
  - data-only FCM messages travel to iOS as background pushes;
  - a revoked access token is re-fetched after a 401;
  - concurrent senders share one access token.

## Web Push

Generate a key pair once:

```sh
go run github.com/EnomotiaGame/push/cmd/vapid@latest
```

Give the browser the public key (`applicationServerKey` in `pushManager.subscribe`) and store the subscription it returns. Then send:

```go
keys, err := webpush.ParseKeys(os.Getenv("VAPID_PUBLIC_KEY"), os.Getenv("VAPID_PRIVATE_KEY"))
sender, err := webpush.New(keys, "mailto:ops@example.com")

sub, err := webpush.ParseSubscription(subscriptionJSON) // PushSubscription.toJSON()
res, err := sender.Send(ctx, sub, []byte(`{"title":"Your order shipped","url":"/orders/42"}`), webpush.Options{
	TTL:     24 * time.Hour,
	Urgency: webpush.Normal,
	Topic:   "order-42", // replaces an undelivered message with the same topic
})
if res.Outcome == webpush.Gone {
	deleteSubscription(sub)
}
```

Your service worker receives the payload as `event.data` and draws the notification. A payload can be up to `webpush.MaxPayload` (3993) bytes.

## Firebase Cloud Messaging

Download a service-account key from the Firebase console (Project settings, Service accounts). To reach iPhones, upload your APNs key to the same Firebase project.

```go
sa, err := fcm.LoadServiceAccount("firebase-service-account.json")
client := fcm.New(sa)

res, err := client.Send(ctx, deviceToken, fcm.Message{
	Title:    "Your order shipped",
	Body:     "It arrives on Friday.",
	Data:     map[string]string{"url": "/orders/42"},
	Collapse: "order-42", // replaces an earlier notification with the same key
	Group:    "orders",   // Android channel id and iOS thread-id
	TTL:      24 * time.Hour,
})
switch res.Outcome {
case fcm.Gone:      // delete the token
case fcm.Transient: // retry after res.RetryAfter
case fcm.Unsent:    // fix your credentials; keep the token
}
```

Leave `Title` and `Body` empty for a silent, data-only message. Use `client.Validate` when an app registers a token, so a dead one is refused before you store it.

Messages through Firebase are not end-to-end encrypted: Google, and Apple for an iPhone, can read them. Put on the lock screen only what you would show there anyway.

## Contributing

Bug reports, ideas and pull requests are welcome. A push service that answers in a way we didn't expect is exactly the kind of report we want. Security problems go through [private vulnerability reporting](https://github.com/EnomotiaGame/push/security/advisories/new), not public issues. The details are in [CONTRIBUTING](https://github.com/EnomotiaGame/.github/blob/main/CONTRIBUTING.md).

## License

MIT © TRUETHINKS LTD

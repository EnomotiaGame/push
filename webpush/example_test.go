package webpush_test

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/EnomotiaGame/push/webpush"
)

func Example() {
	keys, err := webpush.ParseKeys(os.Getenv("VAPID_PUBLIC_KEY"), os.Getenv("VAPID_PRIVATE_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	sender, err := webpush.New(keys, "mailto:ops@example.com")
	if err != nil {
		log.Fatal(err)
	}

	// What the browser's pushManager.subscribe() returned, sent to your server
	// as JSON and stored there.
	stored := []byte(`{"endpoint":"https://fcm.googleapis.com/fcm/send/…","keys":{"p256dh":"…","auth":"…"}}`)
	sub, err := webpush.ParseSubscription(stored)
	if err != nil {
		log.Fatal(err)
	}

	payload, _ := json.Marshal(map[string]string{"title": "Your order shipped", "url": "/orders/42"})
	res, err := sender.Send(context.Background(), sub, payload, webpush.Options{
		TTL:     24 * time.Hour,
		Urgency: webpush.Normal,
		Topic:   "order-42",
	})
	switch res.Outcome {
	case webpush.Delivered:
	case webpush.Gone:
		// The browser unsubscribed: delete the subscription.
	case webpush.Transient:
		// Retry after res.RetryAfter.
	default:
		log.Printf("push failed: %v", err)
	}
}

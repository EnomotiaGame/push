package fcm_test

import (
	"context"
	"log"
	"time"

	"github.com/EnomotiaGame/push/fcm"
)

func Example() {
	sa, err := fcm.LoadServiceAccount("firebase-service-account.json")
	if err != nil {
		log.Fatal(err)
	}
	client := fcm.New(sa)

	res, err := client.Send(context.Background(), "device-registration-token", fcm.Message{
		Title:    "Your order shipped",
		Body:     "It arrives on Friday.",
		Data:     map[string]string{"url": "/orders/42"},
		Collapse: "order-42",
		Group:    "orders",
		TTL:      24 * time.Hour,
	})
	switch res.Outcome {
	case fcm.Delivered:
	case fcm.Gone:
		// Delete the token.
	case fcm.Transient:
		// Retry after res.RetryAfter.
	case fcm.Unsent:
		// Your credentials were refused: fix the configuration, keep the token.
	default:
		log.Printf("push failed: %v", err)
	}
}

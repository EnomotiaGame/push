// Command vapid prints a new VAPID key pair for Web Push.
//
//	go run github.com/EnomotiaGame/push/cmd/vapid@latest
//
// Keep the private key secret and generate the pair once: every browser
// subscription is bound to the public key, and a new pair makes them all stop
// working.
package main

import (
	"fmt"
	"os"

	"github.com/EnomotiaGame/push/webpush"
)

func main() {
	public, private, err := webpush.GenerateKeys()
	if err != nil {
		fmt.Fprintln(os.Stderr, "vapid:", err)
		os.Exit(1)
	}
	fmt.Println("VAPID_PUBLIC_KEY=" + public)
	fmt.Println("VAPID_PRIVATE_KEY=" + private)
}

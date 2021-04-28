package pwned

import (
	"fmt"
	"testing"
)

func TestIsPwned(t *testing.T) {
	t.Skip("local testing")

	result, err := IsPwned("password1")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Pwned:     %v\n", result.Pwned)
	fmt.Printf("Frequency: %v\n", result.Frequency)
	fmt.Printf("Hash:      %v\n", result.Sha1Hash)
}

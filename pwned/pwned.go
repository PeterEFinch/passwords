package pwned

import (
	"crypto/sha1"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const (
	// The length of the prefix which will be compared
	comparisonLength = 5

	// The base URL to check if the password has been pwned.
	urlBase = "https://api.pwnedpasswords.com"
)

// Result represents a result from the Pwned Password service.
type Result struct {
	Pwned     bool   // Pwned represents if the password has been seen at least once.
	Frequency uint64 // Frequency represents the number of times this password has been recorded on  the pwned password service.
	Sha1Hash  string // Sha1Hash is the (full) sha1 hash of the password
}

// SearchPrefix will check if the sha1 prefix provided appears in Troy Hunt's
// https://haveibeenpwned.com/Passwords.
func SearchPrefix(prefix string) ([]Result, error) {
	// Call to the IsPwned URL.
	url := fmt.Sprintf("%s/range/%s", urlBase, prefix)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	// Turns the body into a csv reader with `:` as the delimiter
	defer func() {
		_ = resp.Body.Close()
	}()
	reader := csv.NewReader(resp.Body)
	reader.Comma = ':'

	// Reads CSV and generates the results
	results := make([]Result, 0)
	for {
		// Read each record from csv
		components, err := reader.Read()
		switch {
		case err == io.EOF:
			return results, nil
		case err != nil:
			return results, fmt.Errorf("invalid data from websites: %w", err)
		}

		// Extracts frequency
		var frequency uint64
		if frequency, err = strconv.ParseUint(components[1], 10, 64); err != nil {
			return nil, err
		}

		results = append(results, Result{
			Pwned:     true,
			Frequency: frequency,
			Sha1Hash:  fmt.Sprintf("%s%s", prefix, components[0]),
		})
	}
}

// IsPwned will check if the password has been pwned using Troy Hunt's
// https://haveibeenpwned.com/Passwords along with k-anonymity.
//
// In this approach the password is hashed and a prefix is sent to the website.
// The password is never stored, logged or sent to the website.
func IsPwned(password string) (*Result, error) {
	if password == "" {
		return nil, fmt.Errorf("no password provided")
	}

	hash, err := sha1Hash(password)
	switch {
	case err != nil:
		return nil, err
	case len(hash) < comparisonLength:
		return nil, fmt.Errorf("hash has insufficient length to perform check")
	}

	// Searches for hashes which have been pwned. The results are checked before
	// the error because having the results containing a matching hash suffices
	// in showing the password has pwned. In the case there is an error but
	// no matching hash we can't determine if the password was pwned or not.
	results, err := SearchPrefix(hash[:comparisonLength])
	for i := range results {
		if results[i].Sha1Hash == hash {
			return &results[i], nil
		}
	}
	if err != nil {
		return nil, err
	}

	return &Result{
		Pwned:     false,
		Frequency: 0,
		Sha1Hash:  hash,
	}, nil
}

// sha1Hash computes the sha1 hash of the password.
func sha1Hash(password string) (string, error) {
	h := sha1.New()
	_, err := h.Write([]byte(password)) //io.WriteString(h, password)
	if err != nil {
		return "", err
	}

	hash := fmt.Sprintf("%x", h.Sum(nil))
	hash = strings.ToUpper(hash)
	return hash, nil
}

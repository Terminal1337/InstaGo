package helpers

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

var firstNames = []string{
	"James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph", "Charles", "Thomas",
	"Christopher", "Daniel", "Matthew", "Anthony", "Donald", "Mark", "Paul", "Steven", "Andrew", "Kenneth",
	"George", "Joshua", "Kevin", "Brian", "Edward", "Ronald", "Timothy", "Jason", "Jeffrey", "Ryan",
}

func EncodeFormData(data map[string]string) string {
	var encodedData []string
	for key, value := range data {
		encodedData = append(encodedData, fmt.Sprintf("%s=%s", key, value))
	}
	return strings.Join(encodedData, "&")
}

type Response struct {
	UsernameSuggestions []string `json:"username_suggestions"`
}

// RandomUsername returns a random username suggestion from the response body
func RandomUsername(body string) (string, error) {
	var resp Response
	err := json.Unmarshal([]byte(body), &resp)
	if err != nil {
		return "", err
	}

	// Seed random number generator
	rand.Seed(time.Now().UnixNano())

	// Select a random username suggestion
	index := rand.Intn(len(resp.UsernameSuggestions))
	return resp.UsernameSuggestions[index], nil
}
func RandomFirstName() string {
	rand.Seed(time.Now().UnixNano())
	index := rand.Intn(len(firstNames))
	return firstNames[index]
}

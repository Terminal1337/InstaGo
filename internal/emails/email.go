package emails

import (
	"encoding/json"
	"fmt"
	"instagram/pkg/logging"
	"io/ioutil"
	"net/http"
	"strings"
)

type Response struct {
	Success bool   `json:"success"`
	Email   string `json:"email"`
	Subject string `json:"subject"`
}

func GetEmail(email string) string {
	var subject string
	resp, err := http.Get(fmt.Sprintf("http://185.91.127.66:8000/api/twitter?email=%s", email))
	if err != nil {
		logging.Logger.Error().
			Err(err).
			Msg("Response Error at Hashflags")
		return ""
	}
	defer resp.Body.Close()

	var data Response
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		logging.Logger.Error().
			Err(err).
			Msg("Error decoding JSON response")
		return ""
	}
	if !data.Success {
		return ""
	}
	if data.Subject != "" {
		subject = strings.Split(data.Subject, " ")[0]
	}
	return subject
}

func Get_Email() string {
	resp, err := http.Get("http://localhost:8000/get_email")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := ioutil.ReadAll(resp.Body)
	if strings.Contains(string(b), "email") {
		email := strings.Split(string(b), `:"`)[1]
		email = strings.Split(email, `"`)[0]
		// fmt.Println(email)
		return email
	} else {
		return ""
	}

}
func GetTempCode(email string) string {
	resp, err := http.Get(fmt.Sprintf("http://localhost:8000/get_code?email=%s", email))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := ioutil.ReadAll(resp.Body)
	if strings.Contains(string(b), "code") {
		code := strings.Split(string(b), `:"`)[1]
		code = strings.Split(email, `"`)[0]
		// fmt.Println(code)
		return code
	} else {
		return ""
	}

}

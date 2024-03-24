package encryptor

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type ResponseBody struct {
	Error    bool   `json:"error"`
	Password string `json:"password"`
}

func GetPasswordFromResponseBody(body string) (string, error) {
	var response ResponseBody
	err := json.Unmarshal([]byte(body), &response)
	if err != nil {
		return "", err
	}
	return response.Password, nil
}

func EncPassword(password string) (string, error) {
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:8080/password/%s", password))
	if err != nil {
		return "", err
	}
	b, _ := ioutil.ReadAll(resp.Body)
	password, err = GetPasswordFromResponseBody(string(b))
	if err != nil {
		return "", err
	}
	return password, nil
}

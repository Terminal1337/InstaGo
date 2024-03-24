package instagram

import (
	"fmt"
	"instagram/internal/emails"
	"instagram/internal/encryptor"
	"instagram/internal/helpers"
	"instagram/pkg/logging"
	"io/ioutil"
	"math/rand"
	"strconv"
	"strings"

	http "github.com/bogdanfinn/fhttp"
	"github.com/google/uuid"

	"github.com/Terminal1337/GoCycle"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

var (
	proxies *GoCycle.Cycle
)

func init() {
	var err error
	proxies, err = GoCycle.NewFromFile("input/proxies.txt")
	if err != nil {
		logging.Logger.Error().
			Str("error", err.Error()).
			Msg("Reading Proxies")
	}
}
func Start() {
	for {
		insta := Instance{}
		insta.CreateFlow()
	}
}
func (insta Instance) CreateFlow() (bool, error) {
	var response bool
	var err error
	insta.proxy = fmt.Sprintf("http://%s", proxies.Next())
	_, err = insta.CreateClient()
	if err != nil {
		logging.Logger.Error().
			Str("error", err.Error()).
			Msg("TLS Client")
		return false, err
	}
	response, err = insta.GetCsrf()
	if err != nil {
		logging.Logger.Error().
			Str("error", err.Error()).
			Msg("Csrf Token")
		return false, err
	}
	if !response {
		logging.Logger.Error().
			Str("log", "Csrf Cookie Not Found").
			Msg("Csrf Token")
		return false, err
	}

	response, err = insta.GetCookies()
	if err != nil {
		logging.Logger.Error().
			Str("error", err.Error()).
			Msg("Cookie Parsing")
		return false, err
	}
	if !response {
		logging.Logger.Error().
			Str("log", "Cookies Not Found").
			Msg("Cookie Parsing")
		return false, err
	}
	response = insta.Get_Email()
	if !response {
		logging.Logger.Error().
			Str("log", "Email Not Found").
			Msg("Temp Mail")
		return false, err
	}
	logging.Logger.Info().
		Str("email", insta.email).
		Msg("[Temp Mail]")

	response, err = insta.AttemptCreate()
	if err != nil {
		logging.Logger.Error().
			Str("error", err.Error()).
			Msg("Attempt Create")
		return false, err
	}
	if !response {
		logging.Logger.Error().
			Str("log", "Error At Create Request").
			Msg("[Attempt Create]")
		return false, err
	}
	logging.Logger.Info().
		Str("email", insta.email).
		Str("username", insta.username).
		Msg("[Creating]")
	response, err = insta.EnterUsername()
	if err != nil {
		logging.Logger.Error().
			Str("error", err.Error()).
			Msg("Enter Username")
		return false, err
	}
	if !response {
		logging.Logger.Error().
			Str("log", "Error At Create Request").
			Msg("[Enter Username]")
		return false, err
	}
	response, err = insta.EnterName()
	if err != nil {
		logging.Logger.Error().
			Str("error", err.Error()).
			Msg("Enter Username")
		return false, err
	}
	if !response {
		logging.Logger.Error().
			Str("log", "Error At Create Request").
			Msg("[Enter Username]")
		return false, err
	}
	response, err = insta.EnterPassword()
	if err != nil {
		logging.Logger.Error().
			Str("error", err.Error()).
			Msg("Enter Passsword")
		return false, err
	}
	if !response {
		logging.Logger.Error().
			Str("log", "Error At Create Request").
			Msg("[Enter Password]")
		return false, err
	}
	response, err = insta.EnterSeamless()
	if err != nil {
		logging.Logger.Error().
			Str("error", err.Error()).
			Msg("Enter Passsword")
		return false, err
	}
	if !response {
		logging.Logger.Error().
			Str("log", "Error At Create Request").
			Msg("[Enter Password]")
		return false, err
	}
	response, err = insta.CheckAge()
	if err != nil {
		logging.Logger.Error().
			Str("error", err.Error()).
			Msg("Enter Passsword")
		return false, err
	}
	if !response {
		logging.Logger.Error().
			Str("log", "Error At Create Request").
			Msg("[Enter Password]")
		return false, err
	}
	fmt.Println(response)
	return true, nil
}

func (insta *Instance) CreateClient() (bool, error) {
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithClientProfile(profiles.Chrome_120),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithProxyUrl(insta.proxy),
	}
	var err error
	insta.client, err = tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		logging.Logger.Error().
			Str("error", err.Error()).
			Msg("Failed to create HTTP client")
		return false, err
	}
	logging.Logger.Info().Msg("HTTP client created successfully")
	return true, nil
}

func (insta *Instance) GetCsrf() (bool, error) {
	req, err := http.NewRequest(http.MethodGet, "https://www.instagram.com/accounts/emailsignup/", nil)
	if err != nil {
		return false, err
	}
	req.Header = http.Header{
		"Accept":                    {"text/html", "application/xhtml+xml", "application/xml;q=0.9", "image/avif", "image/webp", "image/apng", "*/*;q=0.8", "application/signed-exchange;v=b3;q=0.7"},
		"Accept-Encoding":           {"gzip", "deflate", "br"},
		"Accept-Language":           {"en-US,en;q=0.9"},
		"Sec-Ch-Ua":                 {"\"Chromium\";v=\"122\", \"Not(A:Brand\";v=\"24\", \"Google Chrome\";v=\"122\""},
		"Sec-Ch-Ua-Mobile":          {"?0"},
		"Sec-Ch-Ua-Platform":        {"\"Windows\""},
		"Sec-Fetch-Dest":            {"document"},
		"Sec-Fetch-Mode":            {"navigate"},
		"Sec-Fetch-Site":            {"none"},
		"Sec-Fetch-User":            {"?1"},
		"Upgrade-Insecure-Requests": {"1"},
		"User-Agent":                {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"},
		http.HeaderOrderKey:         {"accept", "accept-encoding", "accept-language", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user", "upgrade-insecure-requests", "user-agent"},
	}

	resp, err := insta.client.Do(req)

	if err != nil {
		return false, err
	}
	b, _ := ioutil.ReadAll(resp.Body)
	err = ioutil.WriteFile("index.html", b, 0644)
	if err != nil {
		fmt.Println("Error:", err)

	}

	if strings.Contains(string(b), `"_js_datr":{"value":"`) {
		var data string
		data = strings.Split(string(b), `"_js_datr":{"value":"`)[1]
		data = strings.Split(data, `"`)[0]
		insta.datr = data

	}
	if strings.Contains(string(b), `data-btmanifest="`) {
		var d string
		d = strings.Split(string(b), `data-btmanifest="`)[1]
		d = strings.Split(d, `_`)[0]
		fmt.Println(d)
		insta.ajax = d
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "csrftoken" {
			insta.csrf = cookie.Value
			return true, nil
		}
	}
	return false, nil

}

func (insta *Instance) GetCookies() (bool, error) {
	req, err := http.NewRequest(http.MethodGet, "https://www.instagram.com/api/v1/web/login_page/", nil)
	if err != nil {
		return false, err
	}
	insta.device_id = uuid.New().String()
	req.Header = http.Header{
		"Accept":                      {"*/*"},
		"Accept-Encoding":             {"gzip", "deflate", "br"},
		"Accept-Language":             {"en-US,en;q=0.9"},
		"Cookie":                      {fmt.Sprintf("csrftoken=%s", insta.csrf)},
		"dpr":                         {"1"},
		"Host":                        {"www.instagram.com"},
		"Referer":                     {"https://www.instagram.com/accounts/emailsignup/"},
		"sec-ch-prefers-color-scheme": {"dark"},
		"sec-ch-ua":                   {"\"Chromium\";v=\"122\", \"Not(A:Brand\";v=\"24\", \"Google Chrome\";v=\"122\""},
		"sec-ch-ua-full-version-list": {"\"Chromium\";v=\"122.0.6261.129\", \"Not(A:Brand\";v=\"24.0.0.0\", \"Google Chrome\";v=\"122.0.6261.129\""},
		"sec-ch-ua-mobile":            {"?0"},
		"sec-ch-ua-model":             {""},
		"sec-ch-ua-platform":          {"\"Windows\""},
		"sec-ch-ua-platform-version":  {"\"10.0.0\""},
		"Sec-Fetch-Dest":              {"empty"},
		"Sec-Fetch-Mode":              {"cors"},
		"Sec-Fetch-Site":              {"same-origin"},
		"User-Agent":                  {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"},
		"viewport-width":              {"1920"},
		"X-ASBD-ID":                   {"129477"},
		"X-CSRFToken":                 {insta.csrf},
		"X-IG-App-ID":                 {"936619743392459"},
		"X-IG-WWW-Claim":              {"0"},
		"X-Requested-With":            {"XMLHttpRequest"},
		"X-Web-Device-Id":             {insta.device_id},
		http.HeaderOrderKey: {
			"accept",
			"accept-encoding",
			"accept-language",
			"connection",
			"cookie",
			"dpr",
			"host",
			"referer",
			"sec-ch-prefers-color-scheme",
			"sec-ch-ua",
			"sec-ch-ua-full-version-list",
			"sec-ch-ua-mobile",
			"sec-ch-ua-model",
			"sec-ch-ua-platform",
			"sec-ch-ua-platform-version",
			"sec-fetch-dest",
			"sec-fetch-mode",
			"sec-fetch-site",
			"user-agent",
			"viewport-width",
			"x-asbd-id",
			"x-csrftoken",
			"x-ig-app-id",
			"x-ig-www-claim",
			"x-requested-with",
			"x-web-device-id",
		},
	}

	resp, err := insta.client.Do(req)
	if err != nil {
		return false, err
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "csrftoken" {
			insta.csrf = cookie.Value
		}
		if cookie.Name == "mid" {
			insta.mid = cookie.Value
		}
		if cookie.Name == "ig_did" {
			insta.ig_did = cookie.Value
		}
	}
	return true, nil

}
func (insta *Instance) Get_Email() bool {
	insta.email = emails.RequestEmailT()
	if insta.email == "" {
		return false
	}

	return true
}
func (insta *Instance) AttemptCreate() (bool, error) {

	data := map[string]string{
		"email":            insta.email,
		"first_name":       "",
		"username":         "",
		"opt_into_one_tap": "false",
	}

	req, err := http.NewRequest(http.MethodPost, "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/", strings.NewReader(helpers.EncodeFormData(data)))
	if err != nil {
		return false, err
	}
	req.Header = http.Header{
		"Accept":                      {"*/*"},
		"Accept-Encoding":             {"gzip, deflate, br"},
		"Accept-Language":             {"en-US,en;q=0.9"},
		"Content-Type":                {"application/x-www-form-urlencoded"},
		"Cookie":                      {fmt.Sprintf("csrftoken=%s; ig_did=%s; datr=%s; mid=%s; ig_nrcb=1", insta.csrf, insta.ig_did, insta.datr, insta.mid)},
		"dpr":                         {"1"},
		"Host":                        {"www.instagram.com"},
		"Origin":                      {"https://www.instagram.com"},
		"Referer":                     {"https://www.instagram.com/accounts/emailsignup/"},
		"sec-ch-prefers-color-scheme": {"dark"},
		"sec-ch-ua":                   {`"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"`},
		"sec-ch-ua-full-version-list": {`"Chromium";v="122.0.6261.129", "Not(A:Brand";v="24.0.0.0", "Google Chrome";v="122.0.6261.129"`},
		"sec-ch-ua-mobile":            {"?0"},
		"sec-ch-ua-model":             {""},
		"sec-ch-ua-platform":          {`"Windows"`},
		"sec-ch-ua-platform-version":  {`"10.0.0"`},
		"Sec-Fetch-Dest":              {"empty"},
		"Sec-Fetch-Mode":              {"cors"},
		"Sec-Fetch-Site":              {"same-origin"},
		"User-Agent":                  {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"},
		"viewport-width":              {"1920"},
		"X-ASBD-ID":                   {"129477"},
		"X-CSRFToken":                 {insta.csrf},
		"X-IG-App-ID":                 {"936619743392459"},
		"X-IG-WWW-Claim":              {"0"},
		"X-Instagram-AJAX":            {insta.ajax},
		"X-Requested-With":            {"XMLHttpRequest"},
		"X-Web-Device-Id":             {insta.device_id},
	}
	resp, err := insta.client.Do(req)
	if err != nil {
		return false, err
	}
	b, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("ATTEMPT CREATE : ", string(b))

	insta.username, err = helpers.RandomUsername(string(b))
	if err != nil {
		return false, nil
	}
	if resp.StatusCode != 200 {
		return false, nil
	}
	return true, nil

}
func (insta *Instance) EnterUsername() (bool, error) {

	data := map[string]string{
		"email":            insta.email,
		"first_name":       "",
		"username":         insta.username,
		"opt_into_one_tap": "false",
	}

	req, err := http.NewRequest(http.MethodPost, "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/", strings.NewReader(helpers.EncodeFormData(data)))
	if err != nil {
		return false, err
	}
	req.Header = http.Header{
		"Accept":                      {"*/*"},
		"Accept-Encoding":             {"gzip, deflate, br"},
		"Accept-Language":             {"en-US,en;q=0.9"},
		"Content-Type":                {"application/x-www-form-urlencoded"},
		"Cookie":                      {fmt.Sprintf("csrftoken=%s; ig_did=%s; datr=%s; mid=%s; ig_nrcb=1", insta.csrf, insta.ig_did, insta.datr, insta.mid)},
		"dpr":                         {"1"},
		"Host":                        {"www.instagram.com"},
		"Origin":                      {"https://www.instagram.com"},
		"Referer":                     {"https://www.instagram.com/accounts/emailsignup/"},
		"sec-ch-prefers-color-scheme": {"dark"},
		"sec-ch-ua":                   {`"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"`},
		"sec-ch-ua-full-version-list": {`"Chromium";v="122.0.6261.129", "Not(A:Brand";v="24.0.0.0", "Google Chrome";v="122.0.6261.129"`},
		"sec-ch-ua-mobile":            {"?0"},
		"sec-ch-ua-model":             {""},
		"sec-ch-ua-platform":          {`"Windows"`},
		"sec-ch-ua-platform-version":  {`"10.0.0"`},
		"Sec-Fetch-Dest":              {"empty"},
		"Sec-Fetch-Mode":              {"cors"},
		"Sec-Fetch-Site":              {"same-origin"},
		"User-Agent":                  {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"},
		"viewport-width":              {"1920"},
		"X-ASBD-ID":                   {"129477"},
		"X-CSRFToken":                 {insta.csrf},
		"X-IG-App-ID":                 {"936619743392459"},
		"X-IG-WWW-Claim":              {"0"},
		"X-Instagram-AJAX":            {insta.ajax},
		"X-Requested-With":            {"XMLHttpRequest"},
		"X-Web-Device-Id":             {insta.device_id},
	}
	resp, err := insta.client.Do(req)
	if err != nil {
		return false, err
	}
	b, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("ENTER USERNAME: ", string(b))
	insta.username, err = helpers.RandomUsername(string(b))
	if err != nil {
		return false, nil
	}
	if resp.StatusCode != 200 {
		return false, nil
	}
	return true, nil

}
func (insta *Instance) EnterName() (bool, error) {
	insta.first_name = helpers.RandomFirstName()
	data := map[string]string{
		"email":            insta.email,
		"first_name":       insta.first_name,
		"username":         insta.username,
		"opt_into_one_tap": "false",
	}

	req, err := http.NewRequest(http.MethodPost, "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/", strings.NewReader(helpers.EncodeFormData(data)))
	if err != nil {
		return false, err
	}
	req.Header = http.Header{
		"Accept":                      {"*/*"},
		"Accept-Encoding":             {"gzip, deflate, br"},
		"Accept-Language":             {"en-US,en;q=0.9"},
		"Content-Type":                {"application/x-www-form-urlencoded"},
		"Cookie":                      {fmt.Sprintf("csrftoken=%s; ig_did=%s; datr=%s; mid=%s; ig_nrcb=1", insta.csrf, insta.ig_did, insta.datr, insta.mid)},
		"dpr":                         {"1"},
		"Host":                        {"www.instagram.com"},
		"Origin":                      {"https://www.instagram.com"},
		"Referer":                     {"https://www.instagram.com/accounts/emailsignup/"},
		"sec-ch-prefers-color-scheme": {"dark"},
		"sec-ch-ua":                   {`"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"`},
		"sec-ch-ua-full-version-list": {`"Chromium";v="122.0.6261.129", "Not(A:Brand";v="24.0.0.0", "Google Chrome";v="122.0.6261.129"`},
		"sec-ch-ua-mobile":            {"?0"},
		"sec-ch-ua-model":             {""},
		"sec-ch-ua-platform":          {`"Windows"`},
		"sec-ch-ua-platform-version":  {`"10.0.0"`},
		"Sec-Fetch-Dest":              {"empty"},
		"Sec-Fetch-Mode":              {"cors"},
		"Sec-Fetch-Site":              {"same-origin"},
		"User-Agent":                  {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"},
		"viewport-width":              {"1920"},
		"X-ASBD-ID":                   {"129477"},
		"X-CSRFToken":                 {insta.csrf},
		"X-IG-App-ID":                 {"936619743392459"},
		"X-IG-WWW-Claim":              {"0"},
		"X-Instagram-AJAX":            {insta.ajax},
		"X-Requested-With":            {"XMLHttpRequest"},
		"X-Web-Device-Id":             {insta.device_id},
	}
	resp, err := insta.client.Do(req)
	if err != nil {
		return false, err
	}
	b, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("ENTER NAME: ", string(b))
	insta.username, err = helpers.RandomUsername(string(b))
	if err != nil {
		return false, nil
	}
	if resp.StatusCode != 200 {
		return false, nil
	}
	return true, nil

}
func (insta *Instance) EnterPassword() (bool, error) {

	insta.password = "Terminaliscute123$"
	enc, err := encryptor.EncPassword(insta.password)
	if err != nil {
		return false, err
	}

	// insta.first_name = helpers.RandomFirstName()
	data := map[string]string{
		"enc_password":     enc,
		"email":            insta.email,
		"first_name":       insta.first_name,
		"username":         insta.username,
		"opt_into_one_tap": "false",
	}
	req, err := http.NewRequest(http.MethodPost, "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/", strings.NewReader(helpers.EncodeFormData(data)))
	if err != nil {
		return false, err
	}

	req.Header = http.Header{
		"Accept":                      {"*/*"},
		"Accept-Encoding":             {"gzip, deflate, br"},
		"Accept-Language":             {"en-US,en;q=0.9"},
		"Content-Type":                {"application/x-www-form-urlencoded"},
		"Cookie":                      {fmt.Sprintf("csrftoken=%s; ig_did=%s; datr=%s; mid=%s; ig_nrcb=1", insta.csrf, insta.ig_did, insta.datr, insta.mid)},
		"dpr":                         {"1"},
		"Host":                        {"www.instagram.com"},
		"Origin":                      {"https://www.instagram.com"},
		"Referer":                     {"https://www.instagram.com/accounts/emailsignup/"},
		"sec-ch-prefers-color-scheme": {"dark"},
		"sec-ch-ua":                   {`"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"`},
		"sec-ch-ua-full-version-list": {`"Chromium";v="122.0.6261.129", "Not(A:Brand";v="24.0.0.0", "Google Chrome";v="122.0.6261.129"`},
		"sec-ch-ua-mobile":            {"?0"},
		"sec-ch-ua-model":             {""},
		"sec-ch-ua-platform":          {`"Windows"`},
		"sec-ch-ua-platform-version":  {`"10.0.0"`},
		"Sec-Fetch-Dest":              {"empty"},
		"Sec-Fetch-Mode":              {"cors"},
		"Sec-Fetch-Site":              {"same-origin"},
		"User-Agent":                  {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"},
		"viewport-width":              {"1920"},
		"X-ASBD-ID":                   {"129477"},
		"X-CSRFToken":                 {insta.csrf},
		"X-IG-App-ID":                 {"936619743392459"},
		"X-IG-WWW-Claim":              {"0"},
		"X-Instagram-AJAX":            {insta.ajax},
		"X-Requested-With":            {"XMLHttpRequest"},
		"X-Web-Device-Id":             {insta.device_id},
	}
	resp, err := insta.client.Do(req)
	if err != nil {
		return false, err
	}
	b, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("ENTER PASSWORD: ", string(b))
	if resp.StatusCode != 200 {
		return false, nil
	}
	return true, nil

}

func (insta *Instance) EnterSeamless() (bool, error) {
	enc, err := encryptor.EncPassword(insta.password)
	if err != nil {
		return false, err
	}
	data := map[string]string{
		"enc_password":           enc,
		"email":                  insta.email,
		"first_name":             insta.first_name,
		"client_id":              insta.mid,
		"seamless_login_enabled": "1",
		"username":               insta.username,
		"opt_into_one_tap":       "false",
	}
	fmt.Println(data)
	req, err := http.NewRequest(http.MethodPost, "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/", strings.NewReader(helpers.EncodeFormData(data)))
	if err != nil {
		return false, err
	}

	req.Header = http.Header{
		"Accept":                      {"*/*"},
		"Accept-Encoding":             {"gzip, deflate, br"},
		"Accept-Language":             {"en-US,en;q=0.9"},
		"Content-Type":                {"application/x-www-form-urlencoded"},
		"Cookie":                      {fmt.Sprintf("csrftoken=%s; ig_did=%s; datr=%s; mid=%s; ig_nrcb=1", insta.csrf, insta.ig_did, insta.datr, insta.mid)},
		"dpr":                         {"1"},
		"Host":                        {"www.instagram.com"},
		"Origin":                      {"https://www.instagram.com"},
		"Referer":                     {"https://www.instagram.com/accounts/emailsignup/"},
		"sec-ch-prefers-color-scheme": {"dark"},
		"sec-ch-ua":                   {`"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"`},
		"sec-ch-ua-full-version-list": {`"Chromium";v="122.0.6261.129", "Not(A:Brand";v="24.0.0.0", "Google Chrome";v="122.0.6261.129"`},
		"sec-ch-ua-mobile":            {"?0"},
		"sec-ch-ua-model":             {""},
		"sec-ch-ua-platform":          {`"Windows"`},
		"sec-ch-ua-platform-version":  {`"10.0.0"`},
		"Sec-Fetch-Dest":              {"empty"},
		"Sec-Fetch-Mode":              {"cors"},
		"Sec-Fetch-Site":              {"same-origin"},
		"User-Agent":                  {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"},
		"viewport-width":              {"1920"},
		"X-ASBD-ID":                   {"129477"},
		"X-CSRFToken":                 {insta.csrf},
		"X-IG-App-ID":                 {"936619743392459"},
		"X-IG-WWW-Claim":              {"0"},
		"X-Instagram-AJAX":            {insta.ajax},
		"X-Requested-With":            {"XMLHttpRequest"},
		"X-Web-Device-Id":             {insta.device_id},
	}
	fmt.Println(req.Header["Cookie"])
	resp, err := insta.client.Do(req)
	if err != nil {
		return false, err
	}
	b, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("ENTER SEAMLESS: ", string(b))
	if resp.StatusCode != 200 {
		return false, nil
	}
	return true, nil

}

func (insta *Instance) CheckAge() (bool, error) {
	randomInRange := func(min, max int) string {
		return strconv.Itoa(rand.Intn(max-min+1) + min)
	}
	insta.day = randomInRange(1, 28)
	insta.month = randomInRange(1, 12)
	insta.year = randomInRange(2000, 2007)
	data := map[string]string{
		"day":   insta.day,
		"month": insta.month,
		"year":  insta.year,
	}
	req, err := http.NewRequest(http.MethodPost, "https://www.instagram.com/api/v1/web/consent/check_age_eligibility/", strings.NewReader(helpers.EncodeFormData(data)))
	if err != nil {
		return false, err
	}

	req.Header = http.Header{
		"Accept":                      {"*/*"},
		"Accept-Encoding":             {"gzip, deflate, br"},
		"Accept-Language":             {"en-US,en;q=0.9"},
		"Content-Type":                {"application/x-www-form-urlencoded"},
		"Cookie":                      {fmt.Sprintf("csrftoken=%s; ig_did=%s; datr=%s; mid=%s; ig_nrcb=1", insta.csrf, insta.ig_did, insta.datr, insta.mid)},
		"dpr":                         {"1"},
		"Host":                        {"www.instagram.com"},
		"Origin":                      {"https://www.instagram.com"},
		"Referer":                     {"https://www.instagram.com/accounts/emailsignup/"},
		"sec-ch-prefers-color-scheme": {"dark"},
		"sec-ch-ua":                   {`"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"`},
		"sec-ch-ua-full-version-list": {`"Chromium";v="122.0.6261.129", "Not(A:Brand";v="24.0.0.0", "Google Chrome";v="122.0.6261.129"`},
		"sec-ch-ua-mobile":            {"?0"},
		"sec-ch-ua-model":             {""},
		"sec-ch-ua-platform":          {`"Windows"`},
		"sec-ch-ua-platform-version":  {`"10.0.0"`},
		"Sec-Fetch-Dest":              {"empty"},
		"Sec-Fetch-Mode":              {"cors"},
		"Sec-Fetch-Site":              {"same-origin"},
		"User-Agent":                  {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"},
		"viewport-width":              {"1920"},
		"X-ASBD-ID":                   {"129477"},
		"X-CSRFToken":                 {insta.csrf},
		"X-IG-App-ID":                 {"936619743392459"},
		"X-IG-WWW-Claim":              {"0"},
		"X-Instagram-AJAX":            {insta.ajax},
		"X-Requested-With":            {"XMLHttpRequest"},
		"X-Web-Device-Id":             {insta.device_id},
	}
	resp, err := insta.client.Do(req)
	if err != nil {
		return false, err
	}
	b, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("CHECK AGE: ", string(b))
	if resp.StatusCode != 200 {
		return false, nil
	}
	return true, nil

}

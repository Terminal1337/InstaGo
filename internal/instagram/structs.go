package instagram

import tls_client "github.com/bogdanfinn/tls-client"

type Instance struct {
	client     tls_client.HttpClient
	email      string
	password   string
	csrf       string
	ig_did     string
	datr       string
	mid        string
	device_id  string
	proxy      string
	username   string
	first_name string
	day        string
	month      string
	year       string
	ajax       string
}

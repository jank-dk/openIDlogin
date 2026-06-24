package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/atotto/clipboard"
)

type IdentityProviderInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type AccessTokenInfo struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`
}

type OpenIDConfiguration struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func openbrowser(url string) error {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		return fmt.Errorf("error starting browser: %w", err)
	}
	return nil
}

func getCodeAndState(l net.Listener) (string, string, error) {
	log.Println("Listening on", l.Addr())
	handler := http.NewServeMux()
	srv := &http.Server{Handler: handler}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		_ = srv.Serve(l)
	}()

	var code string
	var state string

	handler.HandleFunc("GET /", func(rw http.ResponseWriter, req *http.Request) {
		values := req.URL.Query()
		code = values.Get("code")
		state = values.Get("state")
		rw.Header().Add("Content-Type", "text/plain")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("Received authentication code. You can close this window\r\n"))
		wg.Done()
	})
	wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	return code, state, srv.Shutdown(ctx)
}

func identityProviderLogin(listenPort int, authorizationUrl, tokenUrl *url.URL, scope, clientID, clientSecret string, httpClient *http.Client) error {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort))
	if err != nil {
		return err
	}
	defer l.Close()
	redirectUri := fmt.Sprintf("http://localhost:%d", listenPort)

	// codeVerifier := make([]byte, 32)
	// if _, err = rand.Read(codeVerifier); err != nil {
	// 	return fmt.Errorf("error generating code verifier: %w", err)
	// }
	// codeChallenge := sha256.Sum256(codeVerifier)

	values := url.Values{}
	values.Add("client_id", clientID)
	values.Add("response_type", "code")
	values.Add("scope", scope)
	values.Add("redirect_uri", redirectUri)
	// values.Add("code_challenge", base64.URLEncoding.EncodeToString(codeChallenge[:]))
	// values.Add("code_challenge_method", "S256")
	authorizationUrl.RawQuery = values.Encode()

	if err = openbrowser(authorizationUrl.String()); err != nil {
		return err
	}

	code, _, err := getCodeAndState(l)
	if err != nil {
		return fmt.Errorf("error getting code from callback: %w", err)
	}

	values = url.Values{}
	values.Add("client_id", clientID)
	values.Add("grant_type", "authorization_code")
	values.Add("redirect_uri", redirectUri)
	// values.Add("code_verifier", base64.URLEncoding.EncodeToString(codeVerifier))
	values.Add("code", code)

	req, err := http.NewRequest("POST", tokenUrl.String(), strings.NewReader(values.Encode()))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	accessTokenInfo, err := ReadJson[AccessTokenInfo](resp)
	if err != nil {
		return fmt.Errorf("failed to get access token: %s", err)
	}

	log.Println("ID token:", accessTokenInfo.IDToken)
	log.Println("Access token:", accessTokenInfo.AccessToken)
	log.Println("Expires:", time.Now().Add(time.Second*time.Duration(accessTokenInfo.ExpiresIn)))
	log.Println("Scope:", accessTokenInfo.Scope)

	return clipboard.WriteAll(accessTokenInfo.IDToken)
}

func main() {
	rootUrlFlag := flag.String("rooturl", "", "Root URL of the identity provider. For auto-discovery using .well-known/openid-configuration")
	authorizeUrlFlag := flag.String("authurl", "", "The authorization url of the identity provider")
	tokenUrlFlag := flag.String("tokenurl", "", "The token url of the identity provider")
	clientIDFlag := flag.String("clientid", "", "The client ID")
	clientSecretFlag := flag.String("clientsecret", "", "The client secret")
	scopeFlag := flag.String("scope", "openid profile email", "The scopes requested")
	listenPortFlag := flag.Int("listenport", 12345, "The port to listen for the code")
	disableCertCheck := flag.Bool("disablecertcheck", false, "Disable TLS certificate checks")

	tr := http.DefaultTransport
	if *disableCertCheck {
		trClone := tr.(*http.Transport).Clone()
		trClone.TLSClientConfig.InsecureSkipVerify = true
		tr = trClone
	}

	client := &http.Client{Transport: tr}

	flag.Parse()

	if *rootUrlFlag != "" {
		rootUrl, err := url.Parse(*rootUrlFlag)
		if err != nil {
			log.Fatalln("Invalid root URL: ", err)
		}

		resp, err := client.Get(rootUrl.JoinPath(".well-known/openid-configuration").String())
		if err != nil {
			log.Fatalln("Failed to get openid-configuration: ", err)
		}

		openidConfig, err := ReadJson[OpenIDConfiguration](resp)
		resp.Body.Close()
		if err != nil {
			log.Fatalln("Failed to read openid-configuration: ", err)
		}
		*authorizeUrlFlag = openidConfig.AuthorizationEndpoint
		*tokenUrlFlag = openidConfig.TokenEndpoint
	}

	if *authorizeUrlFlag == "" {
		log.Fatalln("No authorize URL specified")
	}
	if *tokenUrlFlag == "" {
		log.Fatalln("No token URL specified")
	}
	if *clientIDFlag == "" {
		log.Fatalln("No client ID specified")
	}
	if *clientSecretFlag == "" {
		log.Fatalln("No client secret specified")
	}

	var err error

	authorizeUrl, err := url.Parse(*authorizeUrlFlag)
	if err != nil {
		log.Fatalln("Invalid authorize URL: ", err)
	}
	tokenUrl, err := url.Parse(*tokenUrlFlag)
	if err != nil {
		log.Fatalln("Invalid token URL: ", err)
	}

	err = identityProviderLogin(*listenPortFlag, authorizeUrl, tokenUrl, *scopeFlag, *clientIDFlag, *clientSecretFlag, client)

	if err != nil {
		log.Println(err)
	}
}

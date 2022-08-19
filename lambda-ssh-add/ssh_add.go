package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"time"

	"github.com/psanford/lambda-ssh-ca/internal/browser"
	"github.com/psanford/lambda-ssh-ca/internal/msgs"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	serverURL = flag.String("url", "http://localhost:1234", "Server url")
)

func main() {
	flag.Parse()

	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		log.Fatalf("SSH_AUTH_SOCK environment variable is not set")
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		log.Fatalf("Connect to SSH_AUTH_SOCK=%s err: %s", sock, err)
	}

	ak, err := fetchCert()
	if err != nil {
		log.Fatal(err)
	}

	ac := agent.NewClient(conn)
	err = ac.Add(*ak)
	if err != nil {
		log.Fatalf("Add key to agent err: %s", err)
	}
}

func fetchCert() (*agent.AddedKey, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ssh key err: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("new signer err: %w", err)
	}

	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if user, err := user.Current(); err == nil {
		username = user.Username
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {

	}
	defer l.Close()

	nonce := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		panic(err)
	}

	nonceString := base64.URLEncoding.EncodeToString(nonce)

	certResult := make(chan string)

	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+nonceString {
			w.WriteHeader(400)
			fmt.Fprintln(w, "nope")
			return
		}

		r.ParseForm()
		cert := r.FormValue("cert")

		select {
		case certResult <- cert:
			fmt.Fprintln(w, "cert loaded")
		case <-ctx.Done():
			fmt.Fprintln(w, "error cancelled")
		}
	}))

	cbURL := "http://" + l.Addr().String() + "/" + nonceString

	signReq := msgs.PleaseSignRequest{
		PublicKey:           signer.PublicKey().Marshal(),
		Host:                hostname,
		Username:            username,
		CompleteCallbackURL: cbURL,
	}

	signReqBody, err := json.Marshal(signReq)
	if err != nil {
		panic(err)
	}

	signURL := *serverURL + "/please_sign"

	resp, err := http.Post(signURL, "application/json", bytes.NewReader(signReqBody))
	if err != nil {
		return nil, fmt.Errorf("please_sign request err: %w", err)
	}

	r := io.LimitReader(resp.Body, 1<<20)
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read please_sign_resp err: %w", err)
	}
	var signResp msgs.PleaseSignResponse
	err = json.Unmarshal(body, &signResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal please_sign_resp err, body: %q, err: %w", body, err)
	}

	browser.Open(signResp.AuthorizeURL)

	var certTxt string
	select {
	case certTxt = <-certResult:
	case <-ctx.Done():
		log.Printf("context timed out")
		return nil, ctx.Err()
	}

	pubKeyCert, err := parseOpenSSHPublicCert([]byte(certTxt))
	if err != nil {
		return nil, fmt.Errorf("parse public key cert err: %w", err)
	}

	secs := pubKeyCert.ValidBefore - uint64(time.Now().Unix())

	addedKey := agent.AddedKey{
		PrivateKey:   key,
		Certificate:  pubKeyCert,
		LifetimeSecs: uint32(secs),
		Comment:      "webcert",
	}

	return &addedKey, nil
}

func parseOpenSSHPublicCert(encoded []byte) (*ssh.Certificate, error) {
	parts := bytes.SplitN(encoded, []byte(" "), 3)
	if len(parts) < 2 {
		return nil, errors.New("public key or certificate not in OpenSSH format")
	}

	decoded, err := base64.StdEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParsePublicKey(decoded)
	if err != nil {
		return nil, err
	}

	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("value is not an ssh certificate")
	}

	return cert, nil
}

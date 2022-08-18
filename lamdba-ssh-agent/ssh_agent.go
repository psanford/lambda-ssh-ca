package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"sync"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/psanford/lambda-ssh-ca/internal/browser"
	"github.com/psanford/lambda-ssh-ca/internal/msgs"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	serverURL  = flag.String("url", "http://localhost:1234", "Server url")
	socketPath = flag.String("l", "", "agent: path of the UNIX socket to listen on")
)

func main() {
	flag.Parse()

	if *socketPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	handler := log15.StreamHandler(os.Stdout, log15.LogfmtFormat())
	log15.Root().SetHandler(handler)
	lgr := log15.New()

	// key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// if err != nil {
	// 	lgr.Error("generate_ssh_key_err", "err", err)
	// 	os.Exit(1)
	// }

	// signer, err := ssh.NewSignerFromKey(key)
	// if err != nil {
	// 	lgr.Error("new_signer_from_key_err", "err", err)
	// 	os.Exit(1)
	// }

	// fmt.Println(signer.PublicKey())

	// hostname, _ := os.Hostname()
	// username := os.Getenv("USER")
	// if user, err := user.Current(); err == nil {
	// 	username = user.Username
	// }

	// req := msgs.SignRequest{
	// 	PublicKey: signer.PublicKey().Marshal(),
	// 	Host:      hostname,
	// 	Username:  username,
	// }

	// resp := makeRequest(req)

	// openBrowser(resp.AuthorizeURL)

	// for i := 0; i < 100; i++ {
	// 	time.Sleep(5 * time.Second)
	// 	result := checkResult(resp.FetchCertURL)
	// 	if result.Status == msgs.SignResultFail {
	// 		lgr.Error("Signature request failed")
	// 		os.Exit(1)
	// 	}
	// 	if result.Status == msgs.SignResultSuccess {
	// 		success = true
	// 		break
	// 	}
	// }

	// pubKeyCert, err := parseOpenSSHPublicKey(signedResp.SignedCert)
	// if err != nil {
	// 	lgr.Error("parse_public_key_cert_err", "err", err)
	// 	os.Exit(1)
	// }

	// privateKey, err := appKey.Private(appKey.Public())
	// if err != nil {
	// 	lgr.Error("get_app_private_key_err", "err", err)
	// 	os.Exit(1)
	// }

	// a := Agent{
	// 	pubKey: pubKeyCert,
	// 	signer: privateKey,
	// }

	// os.Remove(*socketPath)
	// l, err := net.Listen("unix", *socketPath)
	// if err != nil {
	// 	log.Fatalln("Failed to listen on UNIX socket:", err)
	// }

	for {
		c, err := l.Accept()
		if err != nil {
			type temporary interface {
				Temporary() bool
			}
			if err, ok := err.(temporary); ok && err.Temporary() {
				delay := 1 * time.Second
				lgr.Error("temp_accept_err", "err", err, "retry_in", delay)
				time.Sleep(delay)
				continue
			}
			lgr.Error("accept_error", "err", err)
			os.Exit(1)
		}
		go a.serveConn(c)
	}
}

func keyToPem(key crypto.PublicKey) string {
	marshalled, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		panic(err)
	}

	canonicalPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: marshalled,
	})

	return string(canonicalPem)
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

type Agent struct {
	mu     sync.Mutex
	pubKey ssh.PublicKey
	cert   *ssh.Certificate
	signer crypto.PrivateKey
}

func (a *Agent) fetchCert() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := uint64(time.Now().Unix())
	if a.cert != nil && now > a.cert.ValidAfter && now < a.cert.ValidBefore {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ssh key err: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return fmt.Errorf("new signer err: %w", err)
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

	http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+nonceString {
			w.WriteHeader(400)
			fmt.Fprintln(w, "nope")
			return
		}

		r.ParseForm()
		cert := r.FormValue("cert")

		select {
		case certResult <- cert:
		case <-ctx.Done():
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
		return fmt.Errorf("please_sign request err: %w", err)
	}

	r := io.LimitReader(resp.Body, 1<<20)
	body, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read please_sign_resp err: %w", err)
	}
	var signResp msgs.PleaseSignResponse
	err = json.Unmarshal(body, &signResp)
	if err != nil {
		return fmt.Errorf("unmarshal please_sign_resp err, body: %q, err: %w", body, err)
	}

	browser.Open(signResp.AuthorizeURL)

	var certTxt string
	select {
	case certTxt = <-certResult:
	case <-ctx.Done():
		return ctx.Err()
	}

	pubKeyCert, err := parseOpenSSHPublicCert([]byte(certTxt))
	if err != nil {
		return fmt.Errorf("parse public key cert err: %w", err)
	}

	a.signer = signer
	a.pubKey = signer.PublicKey()
	a.cert = pubKeyCert

	return nil
}

// List returns the identities known to the agent.
func (a *Agent) List() ([]*agent.Key, error) {
	if a.pubKey == nil {
		err := a.fetchCert()
		if err != nil {
			return nil, err
		}
	}
	return []*agent.Key{{
		Format:  a.pubKey.Type(),
		Blob:    a.pubKey.Marshal(),
		Comment: fmt.Sprintf("TPM cert"),
	}}, nil
}

func (a *Agent) serveConn(c net.Conn) {
	lgr := log15.New()
	if err := agent.ServeAgent(a, c); err != io.EOF {
		lgr.Error("agent_conn_err", "err", err)
	}
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if a.pubKey == nil {
		err := a.fetchCert()
		if err != nil {
			return nil, err
		}
	}

	if !bytes.Equal(a.pubKey.Marshal(), key.Marshal()) {
		return nil, fmt.Errorf("no private keys match the requested public key")
	}

	signer, err := ssh.NewSignerFromKey(a.signer)
	if err != nil {
		return nil, fmt.Errorf("get ssh signer err: %w", err)
	}

	cert, ok := a.pubKey.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("public key is not an ssh.Certificate")
	}

	signer, err = ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, fmt.Errorf("new cert signer err: %w", err)
	}

	lgr := log15.New()
	lgr.Info("sign_req", "alg", key.Type(), "flags", flags, "signer", signer.PublicKey().Type())

	return signer.Sign(rand.Reader, data)
}

var ErrOperationUnsupported = errors.New("operation unsupported")

// Add adds a private key to the agent.
func (a *Agent) Add(key agent.AddedKey) error {
	return ErrOperationUnsupported
}

// Remove removes all identities with the given public key.
func (a *Agent) Remove(key ssh.PublicKey) error {
	return ErrOperationUnsupported
}

// RemoveAll removes all identities.
func (a *Agent) RemoveAll() error {
	return ErrOperationUnsupported
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list.
func (a *Agent) Lock(passphrase []byte) error {
	return ErrOperationUnsupported
}

// Unlock undoes the effect of Lock
func (a *Agent) Unlock(passphrase []byte) error {
	return ErrOperationUnsupported
}

// Signers returns signers for all the known keys.
func (a *Agent) Signers() ([]ssh.Signer, error) {
	signer, err := ssh.NewSignerFromKey(a.signer)
	if err != nil {
		return nil, fmt.Errorf("get ssh signer err: %w", err)
	}
	return []ssh.Signer{signer}, nil
}

package main

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"time"

	_ "embed"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/inconshreveable/log15"
	"github.com/psanford/kmssigner"
	"github.com/psanford/lambda-ssh-ca/internal/msgs"
	"github.com/psanford/lambdahttp/lambdahttpv2"
	"github.com/psanford/logmiddleware"
	"golang.org/x/crypto/ssh"
)

var (
	addr    = flag.String("listen-addr", "127.0.0.1:1234", "Host/Port to listen on")
	cliMode = flag.String("mode", "lambda", "execution mode: http|lambda")

	//go:embed templates/*
	templateFiles embed.FS
)

func main() {
	flag.Parse()

	handler := log15.StreamHandler(os.Stdout, log15.LogfmtFormat())
	log15.Root().SetHandler(handler)

	stateBucket := os.Getenv("S3_STATE_BUCKET")
	statePrefix := os.Getenv("S3_STATE_DIR")

	if stateBucket == "" {
		panic("S3_STATE_BUCKET env variable not set")
	}

	kv := newKV()
	authURL := kv.mustGet("authorize_url")
	if authURL == "" {
		panic("authorize_url not set in parameter store")
	}

	keyARN := kv.mustGet("kms_arn")
	if keyARN == "" {
		panic("kms_arn not set in parameter store")
	}

	sess := session.Must(session.NewSession())
	s3client := s3.New(sess)

	kmsClient := kms.New(sess)

	signer, err := kmssigner.New(kmsClient, keyARN)
	if err != nil {
		log.Fatal(err)
	}

	templ, err := template.ParseFS(templateFiles, "templates/*")
	if err != nil {
		log.Fatal(err)
	}

	sshSinger, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		panic(err)
	}

	caPubKey := ssh.MarshalAuthorizedKey(sshSinger.PublicKey())
	log.Printf("ca key: %s", caPubKey)

	s := &server{
		stateBucket: stateBucket,
		statePrefix: statePrefix,
		authURL:     authURL,
		s3:          s3client,
		templates:   templ,
		caKey:       sshSinger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ssh-ca/please_sign", s.challengeHandler)
	mux.HandleFunc("/ssh-ca/authorize", s.authorizeHandler)

	h := logmiddleware.New(mux)

	switch *cliMode {
	case "http":
		fmt.Printf("Listening on %s\n", *addr)
		panic(http.ListenAndServe(*addr, h))
	default:
		lambda.Start(lambdahttpv2.NewLambdaHandler(h))
	}
}

type server struct {
	stateBucket string
	statePrefix string
	authURL     string
	caKey       ssh.Signer
	s3          *s3.S3
	templates   *template.Template
}

func (s *server) challengeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	lgr := logmiddleware.LgrFromContext(r.Context())
	now := time.Now()

	dec := json.NewDecoder(r.Body)
	var pleaseSignReq msgs.PleaseSignRequest
	err := dec.Decode(&pleaseSignReq)
	if err != nil {
		lgr.Error("decode_please_sign_req_err", "err", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	pleaseSignReq.ClientAddr = r.RemoteAddr
	pleaseSignReq.ReqTime = now

	pub, err := ssh.ParsePublicKey(pleaseSignReq.PublicKey)
	if err != nil {
		lgr.Error("decode_public_key_err", "err", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	fingerPrint := ssh.FingerprintSHA256(pub)

	reqIDBytes := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, reqIDBytes)
	if err != nil {
		panic(err)
	}

	reqID := base64.RawURLEncoding.EncodeToString(reqIDBytes)

	pendingPath := path.Join(s.statePrefix, "pending_requests", reqID)

	expiration := now.Add(24 * time.Hour)

	marshalledReq, err := json.Marshal(pleaseSignReq)
	if err != nil {
		panic(err)
	}

	_, err = s.s3.PutObject(&s3.PutObjectInput{
		Bucket:  &s.stateBucket,
		Key:     &pendingPath,
		Expires: &expiration,
		Body:    bytes.NewReader(marshalledReq),
	})
	if err != nil {
		lgr.Error("save_req_err", "err", err, "bucket", s.stateBucket, "path", pendingPath)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	auditEvent := AuditEvent{
		Time:              now,
		EventType:         AuditEventPleaseSignRequest,
		ID:                reqID,
		PleaseSignRequest: pleaseSignReq,
		PubKeyFingerprint: fingerPrint,
	}

	err = s.saveAudit(auditEvent)
	if err != nil {
		lgr.Error("save_audit_log_err", "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	resp := msgs.PleaseSignResponse{
		AuthorizeURL: s.authURL + "?id=" + reqID,
	}

	json.NewEncoder(w).Encode(resp)
}

func (s *server) authorizeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		s.authorizeHandlerPost(w, r)
	} else {
		s.authorizeHandlerGet(w, r)
	}
}
func (s *server) authorizeHandlerGet(w http.ResponseWriter, r *http.Request) {
	lgr := logmiddleware.LgrFromContext(r.Context())
	r.ParseForm()

	reqID := r.FormValue("id")
	if reqID == "" {
		http.Error(w, "Bad Request", 400)
		fmt.Fprintf(w, "Missing id")
		return
	}

	lambdaReq := lambdahttpv2.APIGWv2ReqFromContext(r.Context())
	if lambdaReq.RequestContext.Authorizer == nil {
		lgr.Error("no authorizer context found")
		http.Error(w, "Internal Error", 500)
		return
	}

	username := lambdaReq.RequestContext.Authorizer.Lambda["pmsauth-username"].(string)
	isSudo := lambdaReq.RequestContext.Authorizer.Lambda["pmsauth-is-sudo"].(bool)

	if username == "" {
		lgr.Error("no username from pmsauth")
		http.Error(w, "Internal Error", 500)
		return
	}

	if !isSudo {
		fmt.Fprintf(w, "You must sudo to perform this action")
		return
	}

	pendingPath := path.Join(s.statePrefix, "pending_requests", reqID)
	obj, err := s.s3.GetObject(&s3.GetObjectInput{
		Bucket: &s.stateBucket,
		Key:    &pendingPath,
	})
	if err != nil {
		lgr.Error("fetch_pending_err", "path", pendingPath, "err", err)
		http.Error(w, "Internal Error", 500)
		return
	}

	var req msgs.PleaseSignRequest
	dec := json.NewDecoder(obj.Body)
	err = dec.Decode(&req)
	if err != nil {
		lgr.Error("decode_pending_err", "path", pendingPath, "err", err)
		http.Error(w, "Internal Error", 500)
		return
	}

	if time.Since(req.ReqTime) > 20*time.Minute {
		lgr.Info("req_too_old", "req_time", req.ReqTime)
		s.s3.DeleteObject(&s3.DeleteObjectInput{
			Bucket: &s.stateBucket,
			Key:    &pendingPath,
		})
		w.Write([]byte("Request too old"))
		return
	}

	pub, err := ssh.ParsePublicKey(req.PublicKey)
	if err != nil {
		lgr.Error("decode_public_key_err", "path", pendingPath, "err", err)
		http.Error(w, "Internal Error", 500)
		return
	}

	fingerPrint := ssh.FingerprintSHA256(pub)
	tmpl := PendingTmpl{
		PleaseSignRequest: req,
		KeyFingerprint:    fingerPrint,
	}

	w.Header().Set("content-type", "text/html; charset=utf-8")
	err = s.templates.ExecuteTemplate(w, "pending.html", tmpl)
	if err != nil {
		lgr.Error("execute_pending_templ_err", "err", err)
		http.Error(w, http.StatusText(500), 500)
		return
	}
}

func (s *server) authorizeHandlerPost(w http.ResponseWriter, r *http.Request) {
	lgr := logmiddleware.LgrFromContext(r.Context())
	r.ParseForm()

	reqID := r.FormValue("id")
	if reqID == "" {
		http.Error(w, "Bad Request", 400)
		fmt.Fprintf(w, "Missing id")
		return
	}

	lambdaReq := lambdahttpv2.APIGWv2ReqFromContext(r.Context())
	if lambdaReq.RequestContext.Authorizer == nil {
		lgr.Error("no authorizer context found")
		http.Error(w, "Internal Error", 500)
		return
	}

	username := lambdaReq.RequestContext.Authorizer.Lambda["pmsauth-username"].(string)
	isSudo := lambdaReq.RequestContext.Authorizer.Lambda["pmsauth-is-sudo"].(bool)

	if username == "" {
		lgr.Error("no username from pmsauth")
		http.Error(w, "Internal Error", 500)
		return
	}

	if !isSudo {
		fmt.Fprintf(w, "You must sudo to perform this action")
		return
	}

	pendingPath := path.Join(s.statePrefix, "pending_requests", reqID)
	obj, err := s.s3.GetObject(&s3.GetObjectInput{
		Bucket: &s.stateBucket,
		Key:    &pendingPath,
	})
	if err != nil {
		lgr.Error("fetch_pending_err", "path", pendingPath, "err", err)
		http.Error(w, "Internal Error", 500)
		return
	}

	var req msgs.PleaseSignRequest
	dec := json.NewDecoder(obj.Body)
	err = dec.Decode(&req)
	if err != nil {
		lgr.Error("decode_pending_err", "path", pendingPath, "err", err)
		http.Error(w, "Internal Error", 500)
		return
	}

	if time.Since(req.ReqTime) > 20*time.Minute {
		lgr.Info("req_too_old", "req_time", req.ReqTime)
		s.s3.DeleteObject(&s3.DeleteObjectInput{
			Bucket: &s.stateBucket,
			Key:    &pendingPath,
		})
		w.Write([]byte("Request too old"))
		return
	}

	pub, err := ssh.ParsePublicKey(req.PublicKey)
	if err != nil {
		lgr.Error("decode_public_key_err", "path", pendingPath, "err", err)
		http.Error(w, "Internal Error", 500)
		return
	}
	fingerPrint := ssh.FingerprintSHA256(pub)

	now := time.Now()
	auditEvent := AuditEvent{
		Time:              now,
		EventType:         AuditEventSignRequest,
		ID:                reqID,
		PleaseSignRequest: req,
		PubKeyFingerprint: fingerPrint,
	}

	err = s.saveAudit(auditEvent)
	if err != nil {
		lgr.Error("save_audit_log_err", "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	keyID := fmt.Sprintf("%s-%d", username, now.UnixMilli())

	principals := []string{username}

	serialBytes := make([]byte, 8)
	rand.Read(serialBytes)
	serial := binary.BigEndian.Uint64(serialBytes)

	lgr = lgr.New("username", username, "key_id", keyID, "principals", principals, "serial", serial)

	expires := time.Now().Add(4 * time.Hour)
	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             pub,
		KeyId:           keyID,
		Serial:          serial,
		ValidAfter:      uint64(time.Now().Add(-5 * time.Minute).Unix()),
		ValidBefore:     uint64(expires.Unix()),
		ValidPrincipals: principals,
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}
	err = cert.SignCert(rand.Reader, s.caKey)
	if err != nil {
		lgr.Error("sign_cert_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	lgr.Info("cert_issued", "valid_before", expires, "fingerprint", ssh.FingerprintSHA256(cert.Key))

	cbURL, err := url.Parse(req.CompleteCallbackURL)
	if err != nil {
		lgr.Error("parse_cb_url_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	signedKey := ssh.MarshalAuthorizedKey(cert)

	q := cbURL.Query()
	q.Add("cert", string(signedKey))
	cbURL.RawQuery = q.Encode()

	http.Redirect(w, r, cbURL.String(), http.StatusTemporaryRedirect)
}

type PendingTmpl struct {
	msgs.PleaseSignRequest
	KeyFingerprint string
}

func (s *server) saveAudit(auditEvent AuditEvent) error {
	marhalledAudit, err := json.Marshal(auditEvent)
	if err != nil {
		panic(err)
	}

	ts := auditEvent.Time.UnixMilli()
	auditEventPath := path.Join(s.statePrefix, "audit", strconv.Itoa(int(ts)))

	_, err = s.s3.PutObject(&s3.PutObjectInput{
		Bucket: &s.stateBucket,
		Key:    &auditEventPath,
		Body:   bytes.NewReader(marhalledAudit),
	})
	return err
}

type Authorizor struct {
	Username string `json:"pmsauth-username"`
	IsSudo   bool   `json:"pmsauth-is-sudo"`
}

type AuditEventType int

const (
	AuditEventPleaseSignRequest AuditEventType = 1
	AuditEventSignRequest       AuditEventType = 2
)

func (t AuditEventType) String() string {
	switch t {
	case AuditEventPleaseSignRequest:
		return "AuditEventPleaseSignRequest"
	case AuditEventSignRequest:
		return "AuditEventSignRequest"
	default:
		return fmt.Sprintf("AuditEventUnknownType<%d>", t)
	}
}

type AuditEvent struct {
	Time              time.Time              `json:"time"`
	EventType         AuditEventType         `json:"event_type"`
	ID                string                 `json:"id"`
	PleaseSignRequest msgs.PleaseSignRequest `json:"please_sign_request"`
	PubKeyFingerprint string                 `json:"public_key_fingerprint"`
}

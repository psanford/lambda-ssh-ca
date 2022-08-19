package msgs

import (
	"time"
)

type PleaseSignRequest struct {
	PublicKey           []byte `json:"public_key"`
	Host                string `json:"host"`
	Username            string `json:"username"`
	CompleteCallbackURL string `json:"complete_callback_url"`

	// client should not set these
	ClientAddr string    `json:"client_addr"`
	ReqTime    time.Time `json:"req_time"`
}

type PleaseSignResponse struct {
	AuthorizeURL string `json:"authorize_url"`
}

type SignResultStatus int

const (
	SignResultPending SignResultStatus = 0
	SignResultSuccess SignResultStatus = 1
	SignResultFail    SignResultStatus = 2
)

type SignResult struct {
	Status      SignResultStatus `json:"status"`
	Certificate []byte           `json:"certificate"`
}

type AuditEventType string

const (
	AuditEventPleaseSignRequest AuditEventType = "please_sign_request"
	AuditEventSignedRequest     AuditEventType = "signed_request"
)

type AuditEvent struct {
	Time              time.Time         `json:"time"`
	EventType         AuditEventType    `json:"event_type"`
	ID                string            `json:"id"`
	PleaseSignRequest PleaseSignRequest `json:"please_sign_request"`
	PubKeyFingerprint string            `json:"public_key_fingerprint"`
}

package slack

import (
	"encoding/json"
	"fmt"

	"github.com/psanford/lambda-ssh-ca/internal/msgs"
	"github.com/slack-go/slack"
)

func PostEvent(url string, msg *msgs.AuditEvent) error {
	jsonObj, err := json.MarshalIndent(msg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal obj err: %w", err)
	}

	hookMsg := slack.WebhookMessage{
		IconEmoji: "lock",
		Username:  "SSH CA",
		Attachments: []slack.Attachment{
			{
				Color: "danger",
				Title: string(msg.EventType),
				Text:  string(jsonObj),
				Fields: []slack.AttachmentField{
					{
						Title: "Host",
						Value: msg.PleaseSignRequest.Host,
						Short: true,
					},
					{
						Title: "Fingerprint",
						Value: msg.PubKeyFingerprint,
						Short: true,
					},
					{
						Title: "Username",
						Value: msg.PleaseSignRequest.Username,
						Short: true,
					},
					{
						Title: "Addr",
						Value: msg.PleaseSignRequest.ClientAddr,
						Short: true,
					},
				},
			},
		},
	}

	return slack.PostWebhook(url, &hookMsg)
}

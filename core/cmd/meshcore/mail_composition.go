package main

import (
	"context"
	"errors"
	"strings"

	"meshtransit.net/core/internal/adapter/sesmail"
	"meshtransit.net/core/internal/adapter/smtpmail"
	"meshtransit.net/core/internal/domain/invitation"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidMailComposition = errors.New("meshcore: invalid mail composition")

// sesInvitationMailer adapts the SES sender to invitations.
type sesInvitationMailer struct{ sender *sesmail.Sender }

func (mailer sesInvitationMailer) Send(ctx context.Context, mail invitation.Mail) error {
	_, err := mailer.sender.Send(ctx, sesmail.Message{To: mail.To, Subject: mail.Subject, Text: mail.Text, HTML: mail.HTML})
	if errors.Is(err, sesmail.ErrRejected) {
		return errors.Join(invitation.ErrMailRejected, err)
	}
	return err
}

// smtpInvitationMailer adapts the SMTP sender to invitations.
type smtpInvitationMailer struct{ sender *smtpmail.Sender }

func (mailer smtpInvitationMailer) Send(ctx context.Context, mail invitation.Mail) error {
	err := mailer.sender.Send(ctx, smtpmail.Message{To: mail.To, Subject: mail.Subject, Text: mail.Text, HTML: mail.HTML})
	if errors.Is(err, smtpmail.ErrRejected) {
		return errors.Join(invitation.ErrMailRejected, err)
	}
	return err
}

// composeInvitationMailer builds the configured transport, reading its secret
// files once at startup. No configuration means invitations are not emailed.
func composeInvitationMailer(settings *config.MailConfig) (invitation.Mailer, error) {
	if settings == nil {
		return nil, nil
	}
	switch settings.Transport {
	case config.MailTransportSES:
		if settings.SES == nil {
			return nil, errInvalidMailComposition
		}
		keyID, err := settings.SES.AccessKeyIDFile.Read()
		if err != nil {
			return nil, errInvalidMailComposition
		}
		secret, err := settings.SES.SecretKeyFile.Read()
		if err != nil {
			return nil, errInvalidMailComposition
		}
		sender, err := sesmail.New(sesmail.Options{
			Region: settings.SES.Region, AccessKeyID: strings.TrimSpace(keyID),
			SecretAccessKey: []byte(strings.TrimSpace(secret)), From: settings.From,
			ConfigurationSet: settings.SES.ConfigurationSet, Timeout: settings.Timeout,
		})
		if err != nil {
			return nil, errInvalidMailComposition
		}
		return sesInvitationMailer{sender: sender}, nil
	case config.MailTransportSMTP:
		if settings.SMTP == nil {
			return nil, errInvalidMailComposition
		}
		options := smtpmail.Options{
			Host: settings.SMTP.Host, Port: settings.SMTP.Port, TLSMode: settings.SMTP.TLS,
			From: settings.From, Timeout: settings.Timeout,
		}
		if settings.SMTP.PasswordFile != nil {
			password, err := settings.SMTP.PasswordFile.Read()
			if err != nil {
				return nil, errInvalidMailComposition
			}
			options.Username, options.Password = settings.SMTP.Username, []byte(password)
		}
		sender, err := smtpmail.New(options)
		if err != nil {
			return nil, errInvalidMailComposition
		}
		return smtpInvitationMailer{sender: sender}, nil
	default:
		return nil, errInvalidMailComposition
	}
}

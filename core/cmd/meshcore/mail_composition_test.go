package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/adapter/sesmail"
	"github.com/meshtransit/meshtransit/core/internal/domain/invitation"
	"github.com/meshtransit/meshtransit/core/internal/platform/config"
)

func TestComposeInvitationMailer(t *testing.T) {
	t.Parallel()
	if mailer, err := composeInvitationMailer(nil); err != nil || mailer != nil {
		t.Fatalf("no mail config = %v, %v", mailer, err)
	}
	directory := t.TempDir()
	write := func(name, value string) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	secretFile := func(name, value string) config.SecretFile {
		file, err := config.NewSecretFile(write(name, value))
		if err != nil {
			t.Fatal(err)
		}
		return file
	}
	ses := &config.MailConfig{
		Transport: config.MailTransportSES, From: "MeshTransit <no-reply@example.com>", Timeout: 15 * time.Second,
		SES: &config.SESMailConfig{Region: "ap-southeast-1", AccessKeyIDFile: secretFile("key", "AKIDEXAMPLE\n"),
			SecretKeyFile: secretFile("secret", "example-secret\n")},
	}
	mailer, err := composeInvitationMailer(ses)
	if err != nil {
		t.Fatalf("ses mailer: %v", err)
	}
	if _, ok := mailer.(sesInvitationMailer); !ok {
		t.Fatalf("mailer = %T", mailer)
	}
	password := secretFile("password", "smtp-pass")
	smtp := &config.MailConfig{
		Transport: config.MailTransportSMTP, From: "no-reply@example.com", Timeout: 15 * time.Second,
		SMTP: &config.SMTPMailConfig{Host: "smtp.example.com", Port: 465, TLS: "tls", Username: "mailer",
			PasswordFile: &password},
	}
	if mailer, err := composeInvitationMailer(smtp); err != nil {
		t.Fatalf("smtp mailer: %v", err)
	} else if _, ok := mailer.(smtpInvitationMailer); !ok {
		t.Fatalf("mailer = %T", mailer)
	}
	missing := *ses
	missingSES := *ses.SES
	missing.SES = &missingSES
	missingSES.AccessKeyIDFile, _ = config.NewSecretFile(filepath.Join(directory, "absent"))
	if _, err := composeInvitationMailer(&missing); !errors.Is(err, errInvalidMailComposition) {
		t.Fatalf("missing key file: %v", err)
	}
}

func TestSESMailerMarksRejections(t *testing.T) {
	t.Parallel()
	sender, err := sesmail.New(sesmail.Options{Region: "ap-southeast-1", AccessKeyID: "AKID",
		SecretAccessKey: []byte("s"), From: "no-reply@example.com", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	mailer := sesInvitationMailer{sender: sender}
	if err := mailer.Send(context.Background(), invitation.Mail{To: "bad"}); errors.Is(err, invitation.ErrMailRejected) {
		t.Fatal("an invalid message is not an SES rejection")
	}
}

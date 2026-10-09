package config

import (
	"errors"
	"testing"
)

func mailLookup(values map[string]string) LookupFunc {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestLoadMailConfig(t *testing.T) {
	t.Parallel()
	ses := map[string]string{ //nolint:gosec // G101: fixtures contain file paths, not credentials.
		envMailTransport: "ses", envMailFrom: "MeshTransit <no-reply@example.com>",
		envMailSESRegion: "ap-southeast-1", envMailSESAccessKeyIDFile: "/run/secrets/ses/key",
		envMailSESSecretKeyFile: "/run/secrets/ses/secret",
	}
	smtp := map[string]string{ //nolint:gosec // G101: fixtures contain file paths, not credentials.
		envMailTransport: "smtp", envMailFrom: "no-reply@example.com", envMailTimeout: "20s",
		envMailSMTPHost: "smtp.example.com", envMailSMTPPort: "587", envMailSMTPTLS: "starttls",
		envMailSMTPUsername: "mailer", envMailSMTPPasswordFile: "/run/secrets/smtp/password",
	}
	with := func(base map[string]string, key, value string) map[string]string {
		copied := map[string]string{}
		for k, v := range base {
			copied[k] = v
		}
		if value == "" {
			delete(copied, key)
		} else {
			copied[key] = value
		}
		return copied
	}
	if got, err := loadMailConfig(mailLookup(map[string]string{})); err != nil || got != nil {
		t.Fatalf("absent = %+v, %v", got, err)
	}
	got, err := loadMailConfig(mailLookup(ses))
	if err != nil || got.SES == nil || got.SMTP != nil || got.SES.Region != "ap-southeast-1" || got.Timeout.Seconds() != 15 {
		t.Fatalf("ses = %+v, %v", got, err)
	}
	got, err = loadMailConfig(mailLookup(smtp))
	if err != nil || got.SMTP == nil || got.SMTP.Port != 587 || got.SMTP.PasswordFile == nil || got.Timeout.Seconds() != 20 {
		t.Fatalf("smtp = %+v, %v", got, err)
	}
	for name, values := range map[string]map[string]string{
		"from without transport": {envMailFrom: "no-reply@example.com"},
		"unknown transport":      with(ses, envMailTransport, "sendgrid"),
		"bad sender":             with(ses, envMailFrom, "nobody"),
		"ses without region":     with(ses, envMailSESRegion, ""),
		"ses same files":         with(ses, envMailSESSecretKeyFile, "/run/secrets/ses/key"),
		"ses with smtp host":     with(ses, envMailSMTPHost, "smtp.example.com"),
		"smtp plaintext":         with(smtp, envMailSMTPTLS, "none"),
		"smtp bad port":          with(smtp, envMailSMTPPort, "0"),
		"smtp user only":         with(smtp, envMailSMTPPasswordFile, ""),
		"smtp long timeout":      with(smtp, envMailTimeout, "5m"),
	} {
		if _, err := loadMailConfig(mailLookup(values)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: error = %v, want invalid", name, err)
		}
	}
}

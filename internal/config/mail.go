package config

import (
	"net/mail"
	"strconv"
	"strings"
	"time"
)

const (
	envMailTransport           = "MESHTRANSIT_MAIL_TRANSPORT"
	envMailFrom                = "MESHTRANSIT_MAIL_FROM"
	envMailTimeout             = "MESHTRANSIT_MAIL_TIMEOUT"
	envMailSESRegion           = "MESHTRANSIT_MAIL_SES_REGION"
	envMailSESAccessKeyIDFile  = "MESHTRANSIT_MAIL_SES_ACCESS_KEY_ID_FILE"
	envMailSESSecretKeyFile    = "MESHTRANSIT_MAIL_SES_SECRET_ACCESS_KEY_FILE"
	envMailSESConfigurationSet = "MESHTRANSIT_MAIL_SES_CONFIGURATION_SET"
	envMailSMTPHost            = "MESHTRANSIT_MAIL_SMTP_HOST"
	envMailSMTPPort            = "MESHTRANSIT_MAIL_SMTP_PORT"
	envMailSMTPTLS             = "MESHTRANSIT_MAIL_SMTP_TLS"
	envMailSMTPUsername        = "MESHTRANSIT_MAIL_SMTP_USERNAME"
	envMailSMTPPasswordFile    = "MESHTRANSIT_MAIL_SMTP_PASSWORD_FILE"
)

// Mail transports.
const (
	MailTransportSES  = "ses"
	MailTransportSMTP = "smtp"
)

// MailConfig selects how product email (Workspace invitations) is sent.
// Absent, invitations are created and their links shown, but not emailed.
type MailConfig struct {
	Transport string
	From      string
	Timeout   time.Duration
	SES       *SESMailConfig
	SMTP      *SMTPMailConfig
}

// SESMailConfig sends through the Amazon SES v2 API over HTTPS.
type SESMailConfig struct {
	Region           string
	AccessKeyIDFile  SecretFile
	SecretKeyFile    SecretFile
	ConfigurationSet string
}

// SMTPMailConfig submits to an SMTP server over implicit TLS or STARTTLS.
type SMTPMailConfig struct {
	Host         string
	Port         int
	TLS          string
	Username     string
	PasswordFile *SecretFile
}

var sesMailSettings = []string{envMailSESRegion, envMailSESAccessKeyIDFile, envMailSESSecretKeyFile,
	envMailSESConfigurationSet}

var smtpMailSettings = []string{envMailSMTPHost, envMailSMTPPort, envMailSMTPTLS, envMailSMTPUsername,
	envMailSMTPPasswordFile}

func loadMailConfig(lookup LookupFunc) (*MailConfig, error) {
	transport, enabled := lookup(envMailTransport)
	if !enabled {
		for _, setting := range append(append([]string{envMailFrom, envMailTimeout}, sesMailSettings...),
			smtpMailSettings...) {
			if _, ok := lookup(setting); ok {
				return nil, settingError(setting)
			}
		}
		return nil, nil
	}
	from, _ := lookup(envMailFrom)
	if address, err := mail.ParseAddress(from); err != nil || address.Address == "" || strings.ContainsAny(from, "\r\n") {
		return nil, settingError(envMailFrom)
	}
	timeout := 15 * time.Second
	if value, ok := lookup(envMailTimeout); ok {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed < time.Second || parsed > time.Minute {
			return nil, settingError(envMailTimeout)
		}
		timeout = parsed
	}
	result := &MailConfig{Transport: transport, From: from, Timeout: timeout}
	switch transport {
	case MailTransportSES:
		if err := rejectSettings(lookup, smtpMailSettings); err != nil {
			return nil, err
		}
		ses, err := loadSESMailConfig(lookup)
		if err != nil {
			return nil, err
		}
		result.SES = ses
	case MailTransportSMTP:
		if err := rejectSettings(lookup, sesMailSettings); err != nil {
			return nil, err
		}
		smtp, err := loadSMTPMailConfig(lookup)
		if err != nil {
			return nil, err
		}
		result.SMTP = smtp
	default:
		return nil, settingError(envMailTransport)
	}
	return result, nil
}

func rejectSettings(lookup LookupFunc, settings []string) error {
	for _, setting := range settings {
		if _, ok := lookup(setting); ok {
			return settingError(setting)
		}
	}
	return nil
}

func loadSESMailConfig(lookup LookupFunc) (*SESMailConfig, error) {
	region, _ := lookup(envMailSESRegion)
	if region == "" || len(region) > 32 || strings.Trim(region, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
		return nil, settingError(envMailSESRegion)
	}
	keyPath, _ := lookup(envMailSESAccessKeyIDFile)
	keyFile, err := NewSecretFile(keyPath)
	if err != nil {
		return nil, settingError(envMailSESAccessKeyIDFile)
	}
	secretPath, _ := lookup(envMailSESSecretKeyFile)
	secretFile, err := NewSecretFile(secretPath)
	if err != nil || secretPath == keyPath {
		return nil, settingError(envMailSESSecretKeyFile)
	}
	set, _ := lookup(envMailSESConfigurationSet)
	if len(set) > 64 || strings.Trim(set, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" {
		return nil, settingError(envMailSESConfigurationSet)
	}
	return &SESMailConfig{Region: region, AccessKeyIDFile: keyFile, SecretKeyFile: secretFile, ConfigurationSet: set},
		nil
}

func loadSMTPMailConfig(lookup LookupFunc) (*SMTPMailConfig, error) {
	host, _ := lookup(envMailSMTPHost)
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /:\r\n") {
		return nil, settingError(envMailSMTPHost)
	}
	portValue, _ := lookup(envMailSMTPPort)
	port, err := strconv.Atoi(portValue)
	if err != nil || port < 1 || port > 65535 {
		return nil, settingError(envMailSMTPPort)
	}
	mode, _ := lookup(envMailSMTPTLS)
	if mode != "tls" && mode != "starttls" {
		return nil, settingError(envMailSMTPTLS)
	}
	result := &SMTPMailConfig{Host: host, Port: port, TLS: mode}
	username, hasUser := lookup(envMailSMTPUsername)
	passwordPath, hasPassword := lookup(envMailSMTPPasswordFile)
	if hasUser != hasPassword || (hasUser && (username == "" || len(username) > 256)) {
		return nil, settingError(envMailSMTPUsername)
	}
	if hasPassword {
		file, err := NewSecretFile(passwordPath)
		if err != nil {
			return nil, settingError(envMailSMTPPasswordFile)
		}
		result.Username, result.PasswordFile = username, &file
	}
	return result, nil
}

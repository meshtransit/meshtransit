// Package selfhost turns the one file a self-hosting operator writes
// (config.yaml) into the settings, secrets and files MeshTransit's processes
// read (docs: self-host-config-design.md). It never weakens what Core's own
// configuration loader checks: everything it renders is validated again by
// that loader.
package selfhost

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrInvalidConfig reports a config.yaml that does not parse or validate.
// The wrapped text names the field, never a value.
var ErrInvalidConfig = errors.New("invalid self-host configuration")

const (
	configVersion      = 1
	maximumConfigBytes = 64 * 1024
	maximumValueBytes  = 1024
)

// Config is config.yaml: what the operator chooses. Everything else is
// derived or generated.
type Config struct {
	Version      int               `yaml:"version"`
	Domain       string            `yaml:"domain"`
	IdentityName string            `yaml:"identity_host"`
	ACMEEmail    string            `yaml:"acme_email"`
	Login        Login             `yaml:"login"`
	FirstAdmin   FirstAdmin        `yaml:"first_admin"`
	Mail         *Mail             `yaml:"mail"`
	Relay        Relay             `yaml:"relay"`
	Advanced     map[string]string `yaml:"advanced"`
}

// Login is the upstream sign-in provider the identity broker federates.
type Login struct {
	Provider         string `yaml:"provider"`
	ClientID         string `yaml:"client_id"`
	ClientSecretFile string `yaml:"client_secret_file"`
}

// FirstAdmin is the Account bootstrap creates, by its provider subject (Core
// never links an Account by email alone).
type FirstAdmin struct {
	Subject     string `yaml:"subject"`
	DisplayName string `yaml:"display_name"`
	Workspace   string `yaml:"workspace"`
}

// Mail sends invitations; without it invitations are not emailed.
type Mail struct {
	SMTP SMTP   `yaml:"smtp"`
	From string `yaml:"from"`
}

// SMTP is the mail server.
type SMTP struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	TLS          string `yaml:"tls"`
	Username     string `yaml:"username"`
	PasswordFile string `yaml:"password_file"`
}

// Relay is the relay that runs on this server.
type Relay struct {
	PublicIPv4 netip.Addr `yaml:"public_ipv4"`
	PublicIPv6 netip.Addr `yaml:"public_ipv6"`
}

// IdentityHost is the identity broker's host name: identity_host, or
// "id." before the domain. It always differs from the domain, which the
// Console login uses.
func (config Config) IdentityHost() string {
	if config.IdentityName != "" {
		return config.IdentityName
	}
	return "id." + config.Domain
}

//go:embed config.sample.yaml
var sampleConfig []byte

// SampleConfig returns the commented config.yaml "setup init" writes.
func SampleConfig() []byte { return bytes.Clone(sampleConfig) }

// ParseConfig reads config.yaml strictly: one document, known fields only,
// no anchors, aliases or merge keys, then validates every field.
func ParseConfig(contents []byte) (Config, error) {
	if len(contents) == 0 || len(contents) > maximumConfigBytes {
		return Config{}, fmt.Errorf("%w: size", ErrInvalidConfig)
	}
	var document yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(&document); err != nil {
		return Config{}, fmt.Errorf("%w: syntax", ErrInvalidConfig)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("%w: more than one document", ErrInvalidConfig)
	}
	if problem := unsafeNode(&document); problem != "" {
		return Config{}, fmt.Errorf("%w: %s", ErrInvalidConfig, problem)
	}
	var config Config
	strict := yaml.NewDecoder(bytes.NewReader(contents))
	strict.KnownFields(true)
	if err := strict.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("%w: unknown field or wrong type", ErrInvalidConfig)
	}
	if err := config.validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func unsafeNode(node *yaml.Node) string {
	if node.Anchor != "" || node.Kind == yaml.AliasNode {
		return "anchors and aliases are not allowed"
	}
	if node.Kind == yaml.MappingNode {
		for index := 0; index+1 < len(node.Content); index += 2 {
			if node.Content[index].Tag == "!!merge" || node.Content[index].Value == "<<" {
				return "merge keys are not allowed"
			}
		}
	}
	for _, child := range node.Content {
		if problem := unsafeNode(child); problem != "" {
			return problem
		}
	}
	return ""
}

var (
	hostLabel    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	settingName  = regexp.MustCompile(`^MESHTRANSIT_[A-Z0-9_]{1,96}$`)
	emailAddress = regexp.MustCompile(`^[^@\s]{1,64}@[a-z0-9.-]{1,253}$`)
)

func invalid(field string) error { return fmt.Errorf("%w: %s", ErrInvalidConfig, field) }

func (config Config) validate() error {
	checks := []struct {
		field string
		ok    bool
	}{
		{"version", config.Version == configVersion},
		{"domain", validHostName(config.Domain)},
		{"identity_host", config.IdentityName == "" || validHostName(config.IdentityName)},
		{"identity_host", !strings.EqualFold(config.IdentityHost(), config.Domain)},
		{"acme_email", config.ACMEEmail == "" || emailAddress.MatchString(config.ACMEEmail)},
		{"login.provider", config.Login.Provider == "google"},
		{"login.client_id", validValue(config.Login.ClientID, 1, 256) && safeEnvValue(config.Login.ClientID)},
		{"login.client_secret_file", validPath(config.Login.ClientSecretFile)},
		{"first_admin.subject", validValue(config.FirstAdmin.Subject, 1, 255)},
		{"first_admin.display_name", validValue(config.FirstAdmin.DisplayName, 1, 128)},
		{"first_admin.workspace", validValue(config.FirstAdmin.Workspace, 1, 64)},
		{"relay.public_ipv4", publicAddress(config.Relay.PublicIPv4, true)},
		{"relay.public_ipv6", !config.Relay.PublicIPv6.IsValid() || publicAddress(config.Relay.PublicIPv6, false)},
	}
	for _, check := range checks {
		if !check.ok {
			return invalid(check.field)
		}
	}
	if config.Mail != nil {
		if err := config.Mail.validate(); err != nil {
			return err
		}
	}
	for name, value := range config.Advanced {
		if !settingName.MatchString(name) || !tunableSetting(name) || !safeEnvValue(value) {
			return invalid("advanced." + name)
		}
	}
	return nil
}

func (mail Mail) validate() error {
	smtp := mail.SMTP
	switch {
	case !emailAddress.MatchString(mail.From) || !safeEnvValue(mail.From):
		return invalid("mail.from")
	case !validHostName(smtp.Host):
		return invalid("mail.smtp.host")
	case smtp.Port < 1 || smtp.Port > 65535:
		return invalid("mail.smtp.port")
	case smtp.TLS != "tls" && smtp.TLS != "starttls":
		return invalid("mail.smtp.tls")
	case (smtp.Username == "") != (smtp.PasswordFile == ""):
		return invalid("mail.smtp.username")
	case smtp.Username != "" && (!validValue(smtp.Username, 1, 256) || !safeEnvValue(smtp.Username) ||
		!validPath(smtp.PasswordFile)):
		return invalid("mail.smtp.password_file")
	}
	return nil
}

func validHostName(name string) bool {
	if len(name) == 0 || len(name) > 253 || strings.ToLower(name) != name {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// validValue accepts printable single-line text of minimum to most bytes.
func validValue(value string, minimum, most int) bool {
	if len(value) < minimum || len(value) > most {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

// OperatorDir holds config.yaml and the secrets the operator supplies; the
// setup command and every container mount it at this same path.
const OperatorDir = "/etc/meshtransit"

// validPath accepts a clean absolute path under OperatorDir.
func validPath(value string) bool {
	return validValue(value, 2, 4096) && path.IsAbs(value) && path.Clean(value) == value &&
		strings.HasPrefix(value, OperatorDir+"/")
}

func publicAddress(address netip.Addr, ipv4 bool) bool {
	return address.IsValid() && address.Is4() == ipv4 && address.IsGlobalUnicast() && !address.IsPrivate() &&
		!address.Is4In6()
}

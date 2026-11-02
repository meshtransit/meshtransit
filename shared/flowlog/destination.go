package flowlog

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Push destination providers (push destinations design §2). S3 and R2 keep
// Credential and the v1 binding.
const (
	ProviderElasticsearch = "elasticsearch"
	ProviderDatadog       = "datadog"
	ProviderKinesis       = "kinesis"
)

// Flavors of an Elasticsearch destination: OpenSearch (and the Wazuh
// indexer) takes no Elastic API key and no require_data_stream.
const (
	FlavorElasticsearch = "elasticsearch"
	FlavorOpenSearch    = "opensearch"
)

// SecretKind names what a push destination's secret holds.
type SecretKind byte

// Secret kinds; their numbers are in sealed bytes, never renumber.
const (
	// SecretAPIKey is an Elastic API key: ID and Key.
	SecretAPIKey SecretKind = 1
	// SecretBasic is a user name (ID) and password (Key).
	SecretBasic SecretKind = 2
	// SecretDatadogKey is a Datadog API key (Key).
	SecretDatadogKey SecretKind = 3
	// SecretAWSKeys is an access key ID (ID) and secret access key (Key).
	SecretAWSKeys SecretKind = 4
)

// destinationInfo labels the v2 binding (push destinations design §5 S1).
const destinationInfo = "meshtransit/log-destination-credential/v2"

// sealedSecretVersion is the first byte of a v2 secret's plaintext.
const sealedSecretVersion = 2

// Ports an Elasticsearch/OpenSearch URL may name: HTTPS, the
// Elasticsearch default and Elastic Cloud's.
var destinationPorts = map[uint16]bool{443: true, 9200: true, 9243: true}

// DatadogSites are the Datadog sites a destination may name (design F8);
// the receiver builds both hosts from it, so no URL is ever taken.
var DatadogSites = []string{
	"datadoghq.com", "us3.datadoghq.com", "us5.datadoghq.com", "datadoghq.eu", "ap1.datadoghq.com",
	"ap2.datadoghq.com",
}

var (
	hostLabel      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	urlPath        = regexp.MustCompile(`^(/[A-Za-z0-9_-]+)*$`)
	awsRegion      = regexp.MustCompile(`^(us|eu|ap|sa|ca|me|af|il|mx)-[a-z]{4,10}-[1-9]$`)
	streamARN      = regexp.MustCompile(`^arn:aws:kinesis:([a-z0-9-]+):([0-9]{12}):stream/([A-Za-z0-9_.-]{1,128})$`)
	targetName     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,254}$`)
	elasticKeyPart = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)
	datadogKey     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	alphanumeric4  = regexp.MustCompile(`^[A-Za-z0-9]{4}$`)
)

// CanonicalURL is an Elasticsearch/OpenSearch URL as Core stores it and
// both sides bind it: https, a lower-case ASCII host name or IPv4 address,
// the port always written (443 when absent; 443, 9200 or 9243), a path of
// letters, digits, "_", "-" and "/" with no trailing slash; no user,
// query or fragment. A host outside ASCII is given in its punycode form.
func CanonicalURL(raw string) (string, error) {
	// No escapes, fragments, queries, users or brackets at all: what is
	// bound is what is typed.
	if raw == "" || len(raw) > 512 || strings.ContainsAny(raw, `%\#?@[]`) ||
		strings.ContainsFunc(raw, func(r rune) bool { return r <= 0x20 || r >= 0x7f }) {
		return "", ErrInvalidCredential
	}
	parsed, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" || parsed.Opaque != "" ||
		parsed.RawPath != "" {
		return "", ErrInvalidCredential
	}
	host := strings.ToLower(parsed.Hostname())
	if !validHost(host) {
		return "", ErrInvalidCredential
	}
	port := uint16(443)
	if text := parsed.Port(); text != "" {
		number, err := strconv.ParseUint(text, 10, 16)
		if err != nil || text != strconv.FormatUint(number, 10) {
			return "", ErrInvalidCredential
		}
		port = uint16(number)
	} else if strings.HasSuffix(parsed.Host, ":") {
		return "", ErrInvalidCredential
	}
	if !destinationPorts[port] {
		return "", ErrInvalidCredential
	}
	path := strings.TrimSuffix(parsed.Path, "/")
	if !urlPath.MatchString(path) {
		return "", ErrInvalidCredential
	}
	return "https://" + host + ":" + strconv.Itoa(int(port)) + path, nil
}

// validHost reports a host name of at least two labels, or an IPv4
// address; IPv6 literals and single labels are refused.
func validHost(host string) bool {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Is4() && address.String() == host
	}
	if len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	// Every top-level domain starts with a letter; "1.2.3.0x4" would be
	// read as an IPv4 address by other parsers (review p1a M1).
	tld := labels[len(labels)-1]
	return tld[0] >= 'a' && tld[0] <= 'z'
}

// ValidDatadogSite reports one of DatadogSites.
func ValidDatadogSite(site string) bool {
	for _, known := range DatadogSites {
		if site == known {
			return true
		}
	}
	return false
}

// ValidAWSRegion reports an AWS region name in the aws partition.
func ValidAWSRegion(region string) bool { return awsRegion.MatchString(region) }

// ParseStreamARN returns the region of a Kinesis data stream ARN in the aws
// partition, and whether the ARN is one.
func ParseStreamARN(arn string) (string, bool) {
	match := streamARN.FindStringSubmatch(arn)
	if match == nil || !ValidAWSRegion(match[1]) {
		return "", false
	}
	return match[1], true
}

// ValidTarget reports an Elasticsearch/OpenSearch data stream or index
// name: lower-case letters, digits, ".", "_" and "-", starting with a
// letter or digit, at most 255 bytes (a subset of both products' rules).
func ValidTarget(target string) bool {
	return targetName.MatchString(target) && target != "." && target != ".."
}

// Secret is a push destination's secret as the receiver uses it. Its
// fields mean what Kind says. It hides itself when printed or encoded, but
// a holder printed with %v shows unexported fields raw: keep a Secret out
// of anything printed.
type Secret struct {
	Kind SecretKind
	ID   string
	Key  string
}

// SecretKinds are the kinds a provider takes.
func SecretKinds(provider string) []SecretKind {
	switch provider {
	case ProviderElasticsearch:
		return []SecretKind{SecretAPIKey, SecretBasic}
	case ProviderDatadog:
		return []SecretKind{SecretDatadogKey}
	case ProviderKinesis:
		return []SecretKind{SecretAWSKeys}
	}
	return nil
}

// Check holds a secret to the bounds of its kind and provider.
func (secret Secret) Check(provider string) error {
	allowed := false
	for _, kind := range SecretKinds(provider) {
		allowed = allowed || kind == secret.Kind
	}
	if !allowed {
		return ErrInvalidCredential
	}
	printable := func(text string, limit int) bool {
		return text != "" && len(text) <= limit && !strings.ContainsFunc(text, func(r rune) bool { return r < 0x21 || r > 0x7e })
	}
	var valid bool
	switch secret.Kind {
	case SecretAPIKey:
		valid = elasticKeyPart.MatchString(secret.ID) && elasticKeyPart.MatchString(secret.Key)
	case SecretBasic:
		valid = printable(secret.ID, 128) && !strings.Contains(secret.ID, ":") && printable(secret.Key, 256)
	case SecretDatadogKey:
		valid = secret.ID == "" && datadogKey.MatchString(secret.Key)
	case SecretAWSKeys:
		valid = accessKeyIDPattern.MatchString(secret.ID) && printable(secret.Key, 256)
	}
	if !valid {
		return ErrInvalidCredential
	}
	return nil
}

// Suffix is what Core shows of the secret: the last four characters of
// the key's ID (the Datadog key itself), or "****" when they are not four
// letters or digits.
func (secret Secret) Suffix() string {
	shown := secret.ID
	if secret.Kind == SecretDatadogKey {
		shown = secret.Key
	}
	if len(shown) < 4 || !alphanumeric4.MatchString(shown[len(shown)-4:]) {
		return "****"
	}
	return shown[len(shown)-4:]
}

// DestinationBinding is what a push destination's sealed secret is bound
// to: opening it under another Workspace, credential, version, provider or
// endpoint fails, so changing where it is sent requires the secret again
// (push destinations design §5 S1).
type DestinationBinding struct {
	WorkspaceID  string // public UUID, canonical lowercase
	CredentialID string // public UUID, canonical lowercase
	Version      int64  // sealed_version
	Provider     string
	// Elasticsearch: URL from CanonicalURL, Flavor, and CAPEM, the custom
	// CA the receiver trusts for it, or none. The PEM itself is bound
	// (hashed into info), never a hash Core serves, so swapping the CA in
	// Core's database does not open the secret (review p1a M2).
	URL    string
	Flavor string
	CAPEM  []byte
	// Datadog.
	Site string
	// Kinesis: Region is the StreamARN's.
	Region    string
	StreamARN string
}

func (binding DestinationBinding) check() error {
	if !canonicalUUID.MatchString(binding.WorkspaceID) || !canonicalUUID.MatchString(binding.CredentialID) ||
		binding.Version < 1 {
		return ErrInvalidCredential
	}
	elastic := binding.URL != "" || binding.Flavor != "" || len(binding.CAPEM) != 0
	kinesis := binding.Region != "" || binding.StreamARN != ""
	switch binding.Provider {
	case ProviderElasticsearch:
		canonical, err := CanonicalURL(binding.URL)
		if err != nil || canonical != binding.URL || binding.Flavor != FlavorElasticsearch && binding.Flavor != FlavorOpenSearch ||
			!validCAPEM(binding.CAPEM) || binding.Site != "" || kinesis {
			return ErrInvalidCredential
		}
	case ProviderDatadog:
		if !ValidDatadogSite(binding.Site) || elastic || kinesis {
			return ErrInvalidCredential
		}
	case ProviderKinesis:
		region, ok := ParseStreamARN(binding.StreamARN)
		if !ok || region != binding.Region || elastic || binding.Site != "" {
			return ErrInvalidCredential
		}
	default:
		return ErrInvalidCredential
	}
	return nil
}

// MaxCAPEM bounds a custom CA.
const MaxCAPEM = 16 << 10

// validCAPEM reports no CA, or a PEM certificate within MaxCAPEM.
func validCAPEM(pem []byte) bool {
	return len(pem) == 0 || len(pem) <= MaxCAPEM && bytes.Contains(pem, []byte("-----BEGIN CERTIFICATE-----"))
}

// CAHash is the lower-case hex SHA-256 of a custom CA PEM, or empty for
// none: what the binding holds of it, and what Core may show.
func CAHash(pem []byte) string {
	if len(pem) == 0 {
		return ""
	}
	sum := sha256.Sum256(pem)
	return hex.EncodeToString(sum[:])
}

// info is HPKE's info string, field by field; every provider writes every
// field, empty where it has none, so no two bindings share one.
func (binding DestinationBinding) info() []byte {
	return []byte(strings.Join([]string{
		destinationInfo, binding.WorkspaceID, binding.CredentialID, strconv.FormatInt(binding.Version, 10),
		binding.Provider, binding.URL, binding.Flavor, CAHash(binding.CAPEM), binding.Site, binding.Region,
		binding.StreamARN,
	}, "\x00"))
}

// usable reports a secret the binding can send: OpenSearch (and the Wazuh
// indexer) takes no Elastic API key (review p1a M3).
func (binding DestinationBinding) usable(secret Secret) bool {
	return binding.Flavor != FlavorOpenSearch || secret.Kind != SecretAPIKey
}

// SealSecret seals a push destination's secret to the receiver's
// credential key for binding.
func SealSecret(receiver *ecdh.PublicKey, secret Secret, binding DestinationBinding) ([]byte, error) {
	if err := binding.check(); err != nil {
		return nil, err
	}
	if err := secret.Check(binding.Provider); err != nil {
		return nil, err
	}
	if !binding.usable(secret) {
		return nil, ErrInvalidCredential
	}
	public, err := hpke.NewDHKEMPublicKey(receiver)
	if err != nil {
		return nil, fmt.Errorf("flowlog: credential key: %w", err)
	}
	plain := make([]byte, 0, 6+len(secret.ID)+len(secret.Key))
	plain = append(plain, sealedSecretVersion, byte(secret.Kind))
	plain = binary.BigEndian.AppendUint16(plain, uint16(len(secret.ID))) //nolint:gosec // ≤ 256, checked above
	plain = append(plain, secret.ID...)
	plain = binary.BigEndian.AppendUint16(plain, uint16(len(secret.Key))) //nolint:gosec // ≤ 256, checked above
	plain = append(plain, secret.Key...)
	defer clear(plain)
	kdf, aead := suite()
	return hpke.Seal(public, kdf, aead, binding.info(), plain)
}

// OpenSecret opens a push destination's sealed secret under its binding.
func OpenSecret(receiver *ecdh.PrivateKey, sealed []byte, binding DestinationBinding) (Secret, error) {
	if err := binding.check(); err != nil {
		return Secret{}, err
	}
	private, err := hpke.NewDHKEMPrivateKey(receiver)
	if err != nil {
		return Secret{}, fmt.Errorf("flowlog: credential key: %w", err)
	}
	kdf, aead := suite()
	plain, err := hpke.Open(private, kdf, aead, binding.info(), sealed)
	if err != nil {
		return Secret{}, ErrSealedCredential
	}
	defer clear(plain)
	if len(plain) < 4 || plain[0] != sealedSecretVersion {
		return Secret{}, ErrSealedCredential
	}
	idLength := int(binary.BigEndian.Uint16(plain[2:]))
	if len(plain) < 4+idLength+2 {
		return Secret{}, ErrSealedCredential
	}
	keyLength := int(binary.BigEndian.Uint16(plain[4+idLength:]))
	if len(plain) != 4+idLength+2+keyLength {
		return Secret{}, ErrSealedCredential
	}
	secret := Secret{Kind: SecretKind(plain[1]), ID: string(plain[4 : 4+idLength]), Key: string(plain[6+idLength:])}
	if secret.Check(binding.Provider) != nil || !binding.usable(secret) {
		return Secret{}, ErrSealedCredential
	}
	return secret, nil
}

// String never shows the secret.
func (secret Secret) String() string { return "flowlog.Secret(…" + secret.Suffix() + ")" }

// GoString never shows the secret.
func (secret Secret) GoString() string { return secret.String() }

// Format never shows the secret.
func (secret Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(secret.String())) }

// LogValue never shows the secret, whatever the handler.
func (secret Secret) LogValue() slog.Value { return slog.StringValue(secret.String()) }

// MarshalJSON refuses: a secret only ever leaves sealed.
func (Secret) MarshalJSON() ([]byte, error) { return nil, errCredentialJSON }

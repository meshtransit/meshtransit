package kubecustody

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"

	"meshtransit.net/core/internal/domain/kubeca"
)

const (
	kmsCustody = "kms"
	// kmsPurpose names, in the encryption context every KMS call carries
	// (and the cloud's log shows), what a data key is for.
	kmsPurpose = "meshtransit-kube-ca-data-key"
)

// KMSClient is the part of the AWS KMS client a KMS custody uses.
type KMSClient interface {
	GenerateDataKey(ctx context.Context, input *kms.GenerateDataKeyInput,
		options ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Encrypt(ctx context.Context, input *kms.EncryptInput, options ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, input *kms.DecryptInput, options ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// KMS wraps data keys with an AWS KMS key (envelope encryption): every
// unwrap is a KMS call the cloud logs, which is the evidence of key use
// audits ask for (K1a4 §15.2). The encryption context binds each data key
// to its purpose, deployment and Network. Keys are named by their full ARN, which
// KMS reports on wrapping; previous keys, kept while moving to another KMS
// key until every data key is wrapped again, still open what they wrapped.
type KMS struct {
	client     KMSClient
	keyARN     string
	previous   map[string]bool
	deployment string
}

var _ kubeca.Custody = (*KMS)(nil)

// NewKMS builds a KMS custody over client for the KMS key keyARN (and,
// while moving, the previous ones) of deployment.
func NewKMS(client KMSClient, keyARN string, previous []string, deployment string) (*KMS, error) {
	if client == nil || !validKeyARN(keyARN) || deployment == "" || len(previous) > maximumPreviousKeys {
		return nil, kubeca.ErrInvalid
	}
	custody := &KMS{client: client, keyARN: keyARN, previous: map[string]bool{}, deployment: deployment}
	for _, key := range previous {
		if !validKeyARN(key) || key == keyARN || custody.previous[key] {
			return nil, kubeca.ErrInvalid
		}
		custody.previous[key] = true
	}
	return custody, nil
}

// validKeyARN accepts a KMS key ARN with its region and account, never an
// alias: what KMS reports on wrapping must equal what is configured.
func validKeyARN(value string) bool {
	parsed, err := arn.Parse(value)
	return err == nil && parsed.Service == "kms" && parsed.Region != "" && parsed.AccountID != "" &&
		strings.HasPrefix(parsed.Resource, "key/") && len(parsed.Resource) > len("key/")
}

// String names the custody's key, never anything secret.
func (custody *KMS) String() string { return "kubecustody.KMS(" + custody.keyARN + ")" }

// context is the encryption context of network's data key: KMS refuses to
// open it under another, and the cloud's log shows which Network it was.
func (custody *KMS) context(network string) map[string]string {
	return map[string]string{"purpose": kmsPurpose, "deployment": custody.deployment, "network": network}
}

// kmsError sorts a KMS failure: a ciphertext or key that does not match is
// an integrity failure, a key that is missing, disabled or not allowed is a
// misconfiguration, anything else may pass.
func kmsError(err error) error {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		switch apiError.ErrorCode() {
		case "InvalidCiphertextException", "IncorrectKeyException":
			return errors.Join(kubeca.ErrInvalid, err)
		case "AccessDeniedException", "NotFoundException", "DisabledException", "KMSInvalidStateException",
			"InvalidKeyUsageException",
			"InvalidArnException", "InvalidGrantTokenException", "UnsupportedOperationException":
			return errors.Join(kubeca.ErrMisconfigured, err)
		}
	}
	return errors.Join(kubeca.ErrUnavailable, err)
}

// NewDataKey implements kubeca.Custody.
func (custody *KMS) NewDataKey(ctx context.Context, network string) (kubeca.DataKey, kubeca.WrappedKey, error) {
	if network == "" {
		return kubeca.DataKey{}, kubeca.WrappedKey{}, kubeca.ErrInvalid
	}
	output, err := custody.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId: &custody.keyARN, KeySpec: types.DataKeySpecAes256, EncryptionContext: custody.context(network),
	})
	if err != nil {
		return kubeca.DataKey{}, kubeca.WrappedKey{}, kmsError(err)
	}
	if output == nil || len(output.Plaintext) != len(kubeca.DataKey{}) || len(output.CiphertextBlob) == 0 ||
		output.KeyId == nil || *output.KeyId != custody.keyARN {
		return kubeca.DataKey{}, kubeca.WrappedKey{}, kubeca.ErrInvalid
	}
	return kubeca.DataKey(output.Plaintext),
		kubeca.WrappedKey{Custody: kmsCustody, KeyID: custody.keyARN, Ciphertext: output.CiphertextBlob}, nil
}

// WrapDataKey implements kubeca.Custody.
func (custody *KMS) WrapDataKey(ctx context.Context, network string, dataKey kubeca.DataKey) (kubeca.WrappedKey, error) {
	if network == "" || dataKey.IsZero() {
		return kubeca.WrappedKey{}, kubeca.ErrInvalid
	}
	output, err := custody.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId: &custody.keyARN, Plaintext: dataKey[:], EncryptionContext: custody.context(network),
	})
	if err != nil {
		return kubeca.WrappedKey{}, kmsError(err)
	}
	if output == nil || len(output.CiphertextBlob) == 0 || output.KeyId == nil || *output.KeyId != custody.keyARN {
		return kubeca.WrappedKey{}, kubeca.ErrInvalid
	}
	return kubeca.WrappedKey{Custody: kmsCustody, KeyID: custody.keyARN, Ciphertext: output.CiphertextBlob}, nil
}

// OpenDataKey implements kubeca.Custody. It opens only what one of its own
// keys wrapped, and names that key to KMS, so a ciphertext of another key
// never opens.
func (custody *KMS) OpenDataKey(ctx context.Context, network string, wrapped kubeca.WrappedKey) (kubeca.DataKey, error) {
	known := wrapped.KeyID == custody.keyARN || custody.previous[wrapped.KeyID]
	if wrapped.Custody != kmsCustody || !known || len(wrapped.Ciphertext) == 0 || network == "" {
		return kubeca.DataKey{}, kubeca.ErrInvalid
	}
	keyARN := wrapped.KeyID
	output, err := custody.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: wrapped.Ciphertext, KeyId: &keyARN, EncryptionContext: custody.context(network),
	})
	if err != nil {
		return kubeca.DataKey{}, kmsError(err)
	}
	if output == nil || len(output.Plaintext) != len(kubeca.DataKey{}) ||
		output.KeyId == nil || *output.KeyId != keyARN {
		return kubeca.DataKey{}, kubeca.ErrInvalid
	}
	return kubeca.DataKey(output.Plaintext), nil
}

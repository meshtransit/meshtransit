package kubecustody

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"

	"meshtransit.net/core/internal/domain/kubeca"
)

const (
	primaryARN  = "arn:aws:kms:ap-southeast-1:111111111111:key/primary"
	previousARN = "arn:aws:kms:ap-southeast-1:111111111111:key/previous"
)

// fakeKMS wraps by prefixing the key ARN and the encryption context, as a
// real KMS binds them, and records every call.
type fakeKMS struct {
	contexts []map[string]string
	decrypts []string
	fail     error
}

func contextTag(context map[string]string) string {
	return context["purpose"] + "/" + context["deployment"] + "/" + context["network"]
}

func (fake *fakeKMS) GenerateDataKey(_ context.Context, input *kms.GenerateDataKeyInput,
	_ ...func(*kms.Options),
) (*kms.GenerateDataKeyOutput, error) {
	if fake.fail != nil {
		return nil, fake.fail
	}
	if input.KeySpec != types.DataKeySpecAes256 {
		return nil, errors.New("wrong key spec")
	}
	fake.contexts = append(fake.contexts, maps.Clone(input.EncryptionContext))
	plaintext := bytes.Repeat([]byte{7}, 32)
	return &kms.GenerateDataKeyOutput{
		Plaintext: plaintext, KeyId: input.KeyId,
		CiphertextBlob: append([]byte(*input.KeyId+"|"+contextTag(input.EncryptionContext)+"|"), plaintext...),
	}, nil
}

func (fake *fakeKMS) Encrypt(_ context.Context, input *kms.EncryptInput,
	_ ...func(*kms.Options),
) (*kms.EncryptOutput, error) {
	if fake.fail != nil {
		return nil, fake.fail
	}
	fake.contexts = append(fake.contexts, maps.Clone(input.EncryptionContext))
	return &kms.EncryptOutput{
		KeyId:          input.KeyId,
		CiphertextBlob: append([]byte(*input.KeyId+"|"+contextTag(input.EncryptionContext)+"|"), input.Plaintext...),
	}, nil
}

func (fake *fakeKMS) Decrypt(_ context.Context, input *kms.DecryptInput,
	_ ...func(*kms.Options),
) (*kms.DecryptOutput, error) {
	if fake.fail != nil {
		return nil, fake.fail
	}
	fake.contexts = append(fake.contexts, maps.Clone(input.EncryptionContext))
	fake.decrypts = append(fake.decrypts, *input.KeyId)
	parts := bytes.SplitN(input.CiphertextBlob, []byte("|"), 3)
	if len(parts) != 3 || string(parts[0]) != *input.KeyId {
		return nil, &smithy.GenericAPIError{Code: "IncorrectKeyException"}
	}
	if string(parts[1]) != contextTag(input.EncryptionContext) {
		return nil, &smithy.GenericAPIError{Code: "InvalidCiphertextException"}
	}
	return &kms.DecryptOutput{Plaintext: parts[2], KeyId: input.KeyId}, nil
}

// A KMS custody asks KMS for each data key and to open it, naming the key
// that wrapped it and binding every call to the deployment, so the cloud's
// log shows each use; it opens only what its own keys wrapped (K1a4 §15.2).
func TestKMSCustodyBindsEveryCall(t *testing.T) {
	t.Parallel()
	fake := &fakeKMS{}
	before, err := NewKMS(fake, previousARN, nil, "dep-1")
	if err != nil {
		t.Fatal(err)
	}
	dataKey, wrapped, err := before.NewDataKey(t.Context(), "net-1")
	if err != nil || wrapped.Custody != "kms" || wrapped.KeyID != previousARN {
		t.Fatalf("NewDataKey() = %+v, %v", wrapped, err)
	}
	moved, err := NewKMS(fake, primaryARN, []string{previousARN}, "dep-1")
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := moved.OpenDataKey(t.Context(), "net-1", wrapped); err != nil || opened != dataKey ||
		fake.decrypts[len(fake.decrypts)-1] != previousARN {
		t.Fatalf("the previous key: %v, decrypts %v", err, fake.decrypts)
	}
	if _, fresh, err := moved.NewDataKey(t.Context(), "net-1"); err != nil || fresh.KeyID != primaryARN {
		t.Fatalf("a moved custody wraps under %q, %v", fresh.KeyID, err)
	}
	for _, context := range fake.contexts {
		if context["purpose"] != "meshtransit-kube-ca-data-key" || context["deployment"] != "dep-1" ||
			context["network"] != "net-1" {
			t.Fatalf("encryption context %v", context)
		}
	}
	stranger, _ := NewKMS(fake, primaryARN, nil, "dep-1")
	for name, wrong := range map[string]kubeca.WrappedKey{
		"unknown key":  wrapped,
		"file wrapped": {Custody: "file", KeyID: primaryARN, Ciphertext: []byte("x")},
		"empty":        {Custody: "kms", KeyID: primaryARN},
	} {
		if _, err := stranger.OpenDataKey(t.Context(), "net-1", wrong); !errors.Is(err, kubeca.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A key moved to another Network does not open: KMS refuses the context,
	// an integrity failure.
	if _, err := moved.OpenDataKey(t.Context(), "net-2", wrapped); !errors.Is(err, kubeca.ErrInvalid) {
		t.Fatalf("another Network's key: %v", err)
	}
	for code, want := range map[string]error{
		"ThrottlingException":   kubeca.ErrUnavailable,
		"AccessDeniedException": kubeca.ErrMisconfigured,
		"DisabledException":     kubeca.ErrMisconfigured,
		"IncorrectKeyException": kubeca.ErrInvalid,
	} {
		fake.fail = &smithy.GenericAPIError{Code: code}
		if _, _, err := moved.NewDataKey(t.Context(), "net-1"); !errors.Is(err, want) {
			t.Errorf("%s: %v", code, err)
		}
	}
	fake.fail = errors.New("connection reset")
	if _, err := moved.OpenDataKey(t.Context(), "net-1", wrapped); !errors.Is(err, kubeca.ErrUnavailable) {
		t.Fatalf("a network failure: %v", err)
	}
	for name, build := range map[string]func() (*KMS, error){
		"alias":         func() (*KMS, error) { return NewKMS(fake, "alias/meshtransit", nil, "dep-1") },
		"loose ARN":     func() (*KMS, error) { return NewKMS(fake, "arn:x:kms::key/", nil, "dep-1") },
		"same previous": func() (*KMS, error) { return NewKMS(fake, primaryARN, []string{primaryARN}, "dep-1") },
		"bad previous":  func() (*KMS, error) { return NewKMS(fake, primaryARN, []string{"alias/old"}, "dep-1") },
		"no deployment": func() (*KMS, error) { return NewKMS(fake, primaryARN, nil, "") },
	} {
		if _, err := build(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A data key is wrapped again under the primary KMS key, bound to its
// Network like every other call.
func TestKMSCustodyWrapsAnExistingKeyAgain(t *testing.T) {
	t.Parallel()
	fake := &fakeKMS{}
	before, err := NewKMS(fake, previousARN, nil, "dep-1")
	if err != nil {
		t.Fatal(err)
	}
	dataKey, wrapped, err := before.NewDataKey(t.Context(), "net-1")
	if err != nil {
		t.Fatal(err)
	}
	moved, err := NewKMS(fake, primaryARN, []string{previousARN}, "dep-1")
	if err != nil {
		t.Fatal(err)
	}
	again, err := moved.WrapDataKey(t.Context(), "net-1", dataKey)
	if err != nil || again.KeyID != primaryARN || again.Custody != "kms" {
		t.Fatalf("WrapDataKey() = %+v, %v", again, err)
	}
	only, err := NewKMS(fake, primaryARN, nil, "dep-1")
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := only.OpenDataKey(t.Context(), "net-1", again); err != nil || opened != dataKey {
		t.Fatalf("the rewrapped key does not open: %v", err)
	}
	if _, err := only.OpenDataKey(t.Context(), "net-1", wrapped); !errors.Is(err, kubeca.ErrInvalid) {
		t.Fatalf("a key of a forgotten previous key opened: %v", err)
	}
	if _, err := moved.WrapDataKey(t.Context(), "net-1", kubeca.DataKey{}); !errors.Is(err, kubeca.ErrInvalid) {
		t.Fatalf("a zero key: %v", err)
	}
	fake.fail = &smithy.GenericAPIError{Code: "AccessDeniedException"}
	if _, err := moved.WrapDataKey(t.Context(), "net-1", dataKey); !errors.Is(err, kubeca.ErrMisconfigured) {
		t.Fatalf("a denied wrap: %v", err)
	}
}

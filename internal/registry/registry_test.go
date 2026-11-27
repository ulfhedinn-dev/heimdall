package registry

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/google/go-containerregistry/pkg/authn"
	corev1 "k8s.io/api/core/v1"
)

type stubProvider struct {
	name   string
	handle bool
	auth   authn.Authenticator
	err    error
}

func (s stubProvider) Name() string          { return s.name }
func (s stubProvider) CanHandle(string) bool { return s.handle }
func (s stubProvider) GetCredentials(context.Context, string) (authn.Authenticator, error) {
	return s.auth, s.err
}

func TestChain(t *testing.T) {
	basic := &authn.Basic{Username: "u", Password: "p"}
	ctx := context.Background()

	auth, err := NewChain().GetCredentials(ctx, "nginx")
	if err != nil || auth != authn.Anonymous {
		t.Fatalf("empty chain: %v %v", auth, err)
	}

	c := NewChain(nil, stubProvider{name: "skip"}, stubProvider{name: "fail", handle: true, err: errors.New("boom")}, stubProvider{name: "ok", handle: true, auth: basic})
	if len(c.Providers) != 3 {
		t.Fatalf("nil provider not filtered")
	}
	if !c.CanHandle("nginx") {
		t.Error("CanHandle should be true")
	}
	auth, err = c.GetCredentials(ctx, "nginx")
	if err != nil || auth != basic {
		t.Fatalf("got %v %v, want basic auth after failed provider", auth, err)
	}

	_, err = NewChain(stubProvider{name: "fail", handle: true, err: errors.New("boom")}).GetCredentials(ctx, "nginx")
	if err == nil {
		t.Fatal("expected error when every matching provider fails")
	}
}

func TestParseRegistry(t *testing.T) {
	cases := map[string]string{
		"nginx":                   "index.docker.io",
		"ghcr.io/org/app:v1":      "ghcr.io",
		"registry.local:5000/a/b": "registry.local:5000",
		"123.dkr.ecr.us-east-1.amazonaws.com/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": "123.dkr.ecr.us-east-1.amazonaws.com",
	}
	for ref, want := range cases {
		got, err := ParseRegistry(ref)
		if err != nil || got != want {
			t.Errorf("ParseRegistry(%q) = %q, %v; want %q", ref, got, err, want)
		}
	}
	if _, err := ParseRegistry("Not A Ref!"); err == nil {
		t.Error("expected error")
	}
}

func TestCanHandle(t *testing.T) {
	gcr := NewGCRProvider()
	for ref, want := range map[string]bool{
		"gcr.io/proj/app":                 true,
		"eu.gcr.io/proj/app":              true,
		"us-docker.pkg.dev/proj/repo/app": true,
		"ghcr.io/org/app":                 false,
		"nginx":                           false,
	} {
		if got := gcr.CanHandle(ref); got != want {
			t.Errorf("gcr.CanHandle(%q) = %v", ref, got)
		}
	}
	e := NewECRProvider()
	for ref, want := range map[string]bool{
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/app:v1":     true,
		"123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn/app:v1": true,
		"ghcr.io/org/app": false,
	} {
		if got := e.CanHandle(ref); got != want {
			t.Errorf("ecr.CanHandle(%q) = %v", ref, got)
		}
	}
}

type fakeECR struct {
	calls int
	token string
}

func (f *fakeECR) GetAuthorizationToken(context.Context, *ecr.GetAuthorizationTokenInput, ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error) {
	f.calls++
	exp := time.Now().Add(12 * time.Hour)
	return &ecr.GetAuthorizationTokenOutput{AuthorizationData: []ecrtypes.AuthorizationData{{AuthorizationToken: &f.token, ExpiresAt: &exp}}}, nil
}

func TestECRCredentialsAreCachedPerRegion(t *testing.T) {
	fake := &fakeECR{token: base64.StdEncoding.EncodeToString([]byte("AWS:secret"))}
	var regions []string
	p := NewECRProvider()
	p.ClientFactory = func(_ context.Context, region string) (ECRClient, error) {
		regions = append(regions, region)
		return fake, nil
	}
	ref := "123456789012.dkr.ecr.eu-west-1.amazonaws.com/app:v1"
	for i := 0; i < 2; i++ {
		auth, err := p.GetCredentials(context.Background(), ref)
		if err != nil {
			t.Fatal(err)
		}
		cfg, _ := auth.Authorization()
		if cfg.Username != "AWS" || cfg.Password != "secret" {
			t.Fatalf("auth = %+v", cfg)
		}
	}
	if fake.calls != 1 || len(regions) != 1 || regions[0] != "eu-west-1" {
		t.Fatalf("calls=%d regions=%v, want one call for eu-west-1", fake.calls, regions)
	}
	if _, err := p.GetCredentials(context.Background(), "ghcr.io/org/app"); !errors.Is(err, ErrNotApplicable) {
		t.Fatalf("err = %v, want ErrNotApplicable", err)
	}
}

type staticResolver struct{ secrets []corev1.Secret }

func (s staticResolver) SecretsForPod(context.Context, string, string) ([]corev1.Secret, error) {
	return s.secrets, nil
}

func TestPullSecretProvider(t *testing.T) {
	dockerCfgJSON := corev1.Secret{
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{"https://ghcr.io/":{"auth":"` +
			base64.StdEncoding.EncodeToString([]byte("bot:tok")) + `"}}}`)},
	}
	legacy := corev1.Secret{
		Type: corev1.SecretTypeDockercfg,
		Data: map[string][]byte{corev1.DockerConfigKey: []byte(`{"docker.io":{"username":"hub","password":"pw"}}`)},
	}
	opaque := corev1.Secret{Type: corev1.SecretTypeOpaque}
	base := NewPullSecretProvider(staticResolver{secrets: []corev1.Secret{opaque, dockerCfgJSON, legacy}})

	// Without a pod the provider is anonymous.
	if auth, _ := base.GetCredentials(context.Background(), "ghcr.io/org/app"); auth != authn.Anonymous {
		t.Fatal("expected anonymous without pod")
	}

	p := base.WithPod("ns", "pod")
	if base.PodName != "" {
		t.Fatal("WithPod must not mutate the base provider")
	}
	for ref, want := range map[string]string{
		"ghcr.io/org/app:v1": "bot:tok",
		"nginx":              "hub:pw",
	} {
		auth, err := p.GetCredentials(context.Background(), ref)
		if err != nil {
			t.Fatal(err)
		}
		cfg, _ := auth.Authorization()
		if cfg.Username+":"+cfg.Password != want {
			t.Errorf("%s: got %s:%s, want %s", ref, cfg.Username, cfg.Password, want)
		}
	}
	if auth, _ := p.GetCredentials(context.Background(), "quay.io/x/y"); auth != authn.Anonymous {
		t.Error("unmatched registry should be anonymous")
	}
}

func TestDecodeAuth(t *testing.T) {
	if _, _, ok := decodeAuth(dockerAuth{}); ok {
		t.Error("empty auth must not decode")
	}
	if _, _, ok := decodeAuth(dockerAuth{Auth: "!!!"}); ok {
		t.Error("invalid base64 must not decode")
	}
	if _, _, ok := decodeAuth(dockerAuth{Auth: base64.StdEncoding.EncodeToString([]byte("nocolon"))}); ok {
		t.Error("missing colon must not decode")
	}
	u, p, ok := decodeAuth(dockerAuth{Auth: base64.StdEncoding.EncodeToString([]byte("a:b:c"))})
	if !ok || u != "a" || p != "b:c" {
		t.Errorf("got %q %q %v", u, p, ok)
	}
}

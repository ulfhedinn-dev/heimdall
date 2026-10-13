package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// PodSecretResolver loads imagePullSecrets referenced by a pod. We take a
// callback rather than coupling to a specific client type so the controller
// can supply either controller-runtime or a cached lister.
type PodSecretResolver interface {
	// SecretsForPod returns the referenced imagePullSecrets for the pod at
	// namespace/name. The returned secrets are expected to be of type
	// kubernetes.io/dockerconfigjson or kubernetes.io/dockercfg.
	SecretsForPod(ctx context.Context, namespace, name string) ([]corev1.Secret, error)
}

// PullSecretProvider resolves credentials from Kubernetes imagePullSecrets.
// It is the last-resort provider in the chain.
type PullSecretProvider struct {
	Resolver PodSecretResolver

	// PodNamespace and PodName identify the pod whose imagePullSecrets to
	// consult. The controller sets these per-reconcile via WithPod.
	PodNamespace string
	PodName      string
}

// NewPullSecretProvider constructs a provider with the given resolver.
func NewPullSecretProvider(r PodSecretResolver) *PullSecretProvider {
	return &PullSecretProvider{Resolver: r}
}

// WithPod returns a shallow copy of the provider targeting the given pod.
// Use this per-reconcile; the base provider is safe to share.
func (p *PullSecretProvider) WithPod(namespace, name string) *PullSecretProvider {
	cp := *p
	cp.PodNamespace = namespace
	cp.PodName = name
	return &cp
}

// Name implements CredentialProvider.
func (p *PullSecretProvider) Name() string { return "imagePullSecrets" }

// CanHandle always returns true: this provider is the fallback.
func (p *PullSecretProvider) CanHandle(_ string) bool { return true }

// GetCredentials resolves credentials from the pod's imagePullSecrets, if any.
// When no secret matches the image's registry, authn.Anonymous is returned so
// unauthenticated pulls can still be attempted for public images.
func (p *PullSecretProvider) GetCredentials(ctx context.Context, imageRef string) (authn.Authenticator, error) {
	if p.Resolver == nil || p.PodName == "" {
		return authn.Anonymous, nil
	}
	host, err := ParseRegistry(imageRef)
	if err != nil {
		return nil, err
	}
	secrets, err := p.Resolver.SecretsForPod(ctx, p.PodNamespace, p.PodName)
	if err != nil {
		return nil, fmt.Errorf("resolve imagePullSecrets: %w", err)
	}
	for _, s := range secrets {
		if auth, ok := extractAuthForHost(&s, host); ok {
			return auth, nil
		}
	}
	return authn.Anonymous, nil
}

// dockerConfigJSON matches the structure of a kubernetes.io/dockerconfigjson secret.
type dockerConfigJSON struct {
	Auths map[string]dockerAuth `json:"auths"`
}

type dockerAuth struct {
	Auth     string `json:"auth,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Email    string `json:"email,omitempty"`
}

func extractAuthForHost(s *corev1.Secret, host string) (authn.Authenticator, bool) {
	candidates := make(map[string]dockerAuth)
	switch s.Type {
	case corev1.SecretTypeDockerConfigJson:
		raw := s.Data[corev1.DockerConfigJsonKey]
		var cfg dockerConfigJSON
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, false
		}
		for k, v := range cfg.Auths {
			candidates[k] = v
		}
	case corev1.SecretTypeDockercfg:
		raw := s.Data[corev1.DockerConfigKey]
		var cfg map[string]dockerAuth
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, false
		}
		for k, v := range cfg {
			candidates[k] = v
		}
	default:
		return nil, false
	}

	for registry, entry := range candidates {
		if !hostMatches(registry, host) {
			continue
		}
		user, pass, ok := decodeAuth(entry)
		if !ok {
			continue
		}
		return &authn.Basic{Username: user, Password: pass}, true
	}
	return nil, false
}

func hostMatches(registryEntry, host string) bool {
	// imagePullSecrets registry entries may include a scheme or trailing slash.
	e := strings.TrimSpace(registryEntry)
	e = strings.TrimPrefix(e, "http://")
	e = strings.TrimPrefix(e, "https://")
	e = strings.TrimRight(e, "/")
	// strip any path segment
	if idx := strings.Index(e, "/"); idx > 0 {
		e = e[:idx]
	}
	if e == host {
		return true
	}
	// Docker Hub idiosyncrasies.
	if (e == "index.docker.io" || e == "docker.io") && (host == "index.docker.io" || host == "docker.io") {
		return true
	}
	return false
}

func decodeAuth(a dockerAuth) (string, string, bool) {
	if a.Username != "" || a.Password != "" {
		return a.Username, a.Password, true
	}
	if a.Auth == "" {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(a.Auth)
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// ControllerRuntimeResolver is a PodSecretResolver backed by a
// controller-runtime client. Kept in this file so the registry package does
// not fan out additional files for a trivial adapter.
type ControllerRuntimeResolver struct {
	Client ctrlclient.Client
}

// SecretsForPod implements PodSecretResolver.
func (r *ControllerRuntimeResolver) SecretsForPod(ctx context.Context, namespace, name string) ([]corev1.Secret, error) {
	if r == nil || r.Client == nil {
		return nil, nil
	}
	var pod corev1.Pod
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &pod); err != nil {
		return nil, err
	}
	out := make([]corev1.Secret, 0, len(pod.Spec.ImagePullSecrets))
	for _, ref := range pod.Spec.ImagePullSecrets {
		var s corev1.Secret
		if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, &s); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

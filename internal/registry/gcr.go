package registry

import (
	"context"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/google"
)

// GCRProvider resolves credentials for Google-managed registries:
//   - gcr.io, *.gcr.io
//   - pkg.dev (Artifact Registry: us-docker.pkg.dev, europe-docker.pkg.dev, etc.)
//
// On GKE with Workload Identity bound to a service account that has
// `roles/artifactregistry.reader` or `roles/storage.objectViewer`, the default
// go-containerregistry Google keychain picks up the Workload Identity token
// automatically.
type GCRProvider struct {
	// Keychain overrides the default Google keychain. When nil, the global
	// google.Keychain is used.
	Keychain authn.Keychain
}

// NewGCRProvider constructs a GCRProvider.
func NewGCRProvider() *GCRProvider { return &GCRProvider{} }

// Name implements CredentialProvider.
func (p *GCRProvider) Name() string { return "gcr" }

// CanHandle returns true for Google Container Registry and Artifact Registry hosts.
func (p *GCRProvider) CanHandle(imageRef string) bool {
	host, err := ParseRegistry(imageRef)
	if err != nil {
		return false
	}
	return isGoogleHost(host)
}

func isGoogleHost(host string) bool {
	switch {
	case host == "gcr.io":
		return true
	case strings.HasSuffix(host, ".gcr.io"):
		return true
	case strings.HasSuffix(host, "-docker.pkg.dev"):
		return true
	case strings.HasSuffix(host, ".pkg.dev"):
		return true
	}
	return false
}

// GetCredentials returns a Google-authenticated authenticator.
func (p *GCRProvider) GetCredentials(ctx context.Context, imageRef string) (authn.Authenticator, error) {
	kc := p.Keychain
	if kc == nil {
		kc = google.Keychain
	}
	host, err := ParseRegistry(imageRef)
	if err != nil {
		return nil, err
	}
	reg, err := resourceForHost(host)
	if err != nil {
		return nil, err
	}
	return kc.Resolve(reg)
}

// resourceForHost wraps a hostname into an authn.Resource. We use a small
// shim rather than depending on name.NewRegistry here to avoid pulling in the
// parser twice.
type registryResource struct{ host string }

func (r registryResource) String() string     { return r.host }
func (r registryResource) RegistryStr() string { return r.host }

func resourceForHost(host string) (authn.Resource, error) {
	return registryResource{host: host}, nil
}

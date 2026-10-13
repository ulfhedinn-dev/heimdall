// Package registry provides pluggable credential providers for resolving pull
// credentials for container images across common registries (ECR, GCR/AR,
// and generic imagePullSecrets).
package registry

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// CredentialProvider resolves an authn.Authenticator for a given image reference.
//
// Providers are tried in order and the first one whose CanHandle returns true
// is used. The imagePullSecrets provider is intended to be last and acts as a
// catch-all fallback.
type CredentialProvider interface {
	// Name is a short human-readable provider identifier (used in logs).
	Name() string

	// CanHandle returns true when this provider is applicable to the given image
	// reference (typically a hostname match).
	CanHandle(imageRef string) bool

	// GetCredentials returns the authenticator to use when pulling or
	// inspecting the given image. Implementations must be safe for concurrent
	// use.
	GetCredentials(ctx context.Context, imageRef string) (authn.Authenticator, error)
}

// Chain tries a sequence of providers and returns the first result that
// matches the image reference. If no provider matches, it returns
// authn.Anonymous.
type Chain struct {
	Providers []CredentialProvider
}

// NewChain constructs a credential provider chain. nil entries are ignored.
func NewChain(providers ...CredentialProvider) *Chain {
	filtered := make([]CredentialProvider, 0, len(providers))
	for _, p := range providers {
		if p != nil {
			filtered = append(filtered, p)
		}
	}
	return &Chain{Providers: filtered}
}

// Name returns a stable identifier for the chain.
func (c *Chain) Name() string { return "chain" }

// CanHandle reports whether any provider in the chain can handle the image.
func (c *Chain) CanHandle(imageRef string) bool {
	for _, p := range c.Providers {
		if p.CanHandle(imageRef) {
			return true
		}
	}
	return false
}

// GetCredentials delegates to the first provider in the chain whose CanHandle
// returns true. If none match it returns authn.Anonymous.
func (c *Chain) GetCredentials(ctx context.Context, imageRef string) (authn.Authenticator, error) {
	var errs []error
	for _, p := range c.Providers {
		if !p.CanHandle(imageRef) {
			continue
		}
		auth, err := p.GetCredentials(ctx, imageRef)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Name(), err))
			continue
		}
		return auth, nil
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return authn.Anonymous, nil
}

// ParseRegistry returns the registry host for an image reference such as
// `123.dkr.ecr.us-east-1.amazonaws.com/app:tag` → `123.dkr.ecr.us-east-1.amazonaws.com`.
// It uses go-containerregistry's name parser so it understands digests, ports,
// and the Docker Hub default.
func ParseRegistry(imageRef string) (string, error) {
	ref, err := name.ParseReference(imageRef, name.WeakValidation)
	if err != nil {
		return "", fmt.Errorf("parse image ref %q: %w", imageRef, err)
	}
	return ref.Context().RegistryStr(), nil
}

// ErrNotApplicable is returned by a provider when it cannot produce
// credentials for the given image (e.g. the hostname does not match).
var ErrNotApplicable = errors.New("provider not applicable to image reference")

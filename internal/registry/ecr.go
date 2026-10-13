package registry

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/google/go-containerregistry/pkg/authn"
)

// ecrHostRE matches account-id.dkr.ecr.<region>.amazonaws.com or the China partition host.
var ecrHostRE = regexp.MustCompile(`^(\d{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com(\.cn)?$`)

// ECRProvider resolves ECR credentials using the AWS SDK. On EKS this picks up
// IRSA (IAM Roles for Service Accounts) credentials automatically via the
// standard AWS SDK credential chain.
type ECRProvider struct {
	// Region overrides the region derived from the image hostname when set.
	// Rarely needed because the hostname already encodes the region.
	Region string

	// ClientFactory returns an ECR client for a given region. Overridable for
	// tests. When nil, a client is built with the default AWS SDK credential
	// chain.
	ClientFactory func(ctx context.Context, region string) (ECRClient, error)

	mu    sync.Mutex
	cache map[string]*cachedToken
}

// ECRClient is the subset of the ECR API used by this provider.
type ECRClient interface {
	GetAuthorizationToken(ctx context.Context, params *ecr.GetAuthorizationTokenInput, optFns ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

type cachedToken struct {
	auth      authn.Authenticator
	expiresAt time.Time
}

// NewECRProvider constructs an ECRProvider with sensible defaults.
func NewECRProvider() *ECRProvider {
	return &ECRProvider{cache: map[string]*cachedToken{}}
}

// Name implements CredentialProvider.
func (p *ECRProvider) Name() string { return "ecr" }

// CanHandle returns true for ECR hostnames in both the standard and China partitions.
func (p *ECRProvider) CanHandle(imageRef string) bool {
	host, err := ParseRegistry(imageRef)
	if err != nil {
		return false
	}
	return ecrHostRE.MatchString(host)
}

// GetCredentials returns a bearer token authenticator for ECR. Tokens are
// cached per-region for ~11h (ECR issues 12h tokens) to avoid rate limits.
func (p *ECRProvider) GetCredentials(ctx context.Context, imageRef string) (authn.Authenticator, error) {
	host, err := ParseRegistry(imageRef)
	if err != nil {
		return nil, err
	}
	m := ecrHostRE.FindStringSubmatch(host)
	if m == nil {
		return nil, fmt.Errorf("%w: %s is not an ECR host", ErrNotApplicable, host)
	}
	region := p.Region
	if region == "" {
		region = m[2]
	}

	if auth, ok := p.getCached(region); ok {
		return auth, nil
	}

	client, err := p.buildClient(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("build ECR client: %w", err)
	}

	out, err := client.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, fmt.Errorf("ecr GetAuthorizationToken: %w", err)
	}
	if len(out.AuthorizationData) == 0 || out.AuthorizationData[0].AuthorizationToken == nil {
		return nil, fmt.Errorf("ecr returned no authorization data")
	}
	data := out.AuthorizationData[0]
	raw, err := base64.StdEncoding.DecodeString(*data.AuthorizationToken)
	if err != nil {
		return nil, fmt.Errorf("decode ecr token: %w", err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed ecr token")
	}
	auth := &authn.Basic{Username: parts[0], Password: parts[1]}
	expiry := time.Now().Add(11 * time.Hour)
	if data.ExpiresAt != nil {
		expiry = data.ExpiresAt.Add(-15 * time.Minute)
	}
	p.setCached(region, auth, expiry)
	return auth, nil
}

func (p *ECRProvider) getCached(region string) (authn.Authenticator, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.cache[region]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.auth, true
}

func (p *ECRProvider) setCached(region string, auth authn.Authenticator, expiresAt time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cache == nil {
		p.cache = map[string]*cachedToken{}
	}
	p.cache[region] = &cachedToken{auth: auth, expiresAt: expiresAt}
}

func (p *ECRProvider) buildClient(ctx context.Context, region string) (ECRClient, error) {
	if p.ClientFactory != nil {
		return p.ClientFactory(ctx, region)
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return ecr.NewFromConfig(cfg), nil
}

// Heimdall is a Kubernetes operator that maintains an inventory of container
// images running on a cluster and continuously scans each unique image for
// known vulnerabilities.
package main

import (
	"flag"
	"os"
	"time"

	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	heimdallv1alpha1 "github.com/ulfhedinn-dev/heimdall/api/v1alpha1"
	"github.com/ulfhedinn-dev/heimdall/internal/alert"
	"github.com/ulfhedinn-dev/heimdall/internal/controller"
	"github.com/ulfhedinn-dev/heimdall/internal/registry"
	"github.com/ulfhedinn-dev/heimdall/internal/scanner"
)

var (
	scheme = runtime.NewScheme()

	// version is set at build time via -ldflags "-X main.version=…".
	version = "dev"
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(heimdallv1alpha1.AddToScheme(scheme))
}

type config struct {
	metricsAddr     string
	probeAddr       string
	enableLeader    bool
	leaderID        string
	scanInterval    time.Duration
	scanConcurrency int
	scanTimeout     time.Duration
	scanCooldown    time.Duration

	slackWebhook string
	minSeverity  string

	trivyCacheDir string
	trivyOffline  bool

	ecrEnabled bool
	ecrRegion  string
	gcrEnabled bool
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&cfg.probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&cfg.enableLeader, "leader-elect", false, "Enable leader election for controller manager.")
	flag.StringVar(&cfg.leaderID, "leader-election-id", "heimdall.heimdall.ulfhedinn.dev", "Leader election resource name.")
	flag.DurationVar(&cfg.scanInterval, "scan-interval", time.Hour, "How often to rescan each unique image digest.")
	flag.IntVar(&cfg.scanConcurrency, "scan-concurrency", 1, "Inventory records reconciled in parallel. Trivy scans themselves always run one at a time.")
	flag.DurationVar(&cfg.scanTimeout, "scan-timeout", 10*time.Minute, "Maximum duration of a single image scan.")
	flag.DurationVar(&cfg.scanCooldown, "scan-cooldown", 30*time.Second, "Pause between consecutive scans, to limit load on small nodes.")

	flag.StringVar(&cfg.slackWebhook, "slack-webhook-url", envOrDefault("HEIMDALL_SLACK_WEBHOOK", ""), "Slack incoming webhook URL. Empty disables alerts.")
	flag.StringVar(&cfg.minSeverity, "min-severity", envOrDefault("HEIMDALL_MIN_SEVERITY", "HIGH"), "Minimum severity for Slack alerts (LOW|MEDIUM|HIGH|CRITICAL).")

	flag.StringVar(&cfg.trivyCacheDir, "trivy-cache-dir", envOrDefault("TRIVY_CACHE_DIR", "/var/cache/heimdall/trivy"), "Trivy cache directory.")
	flag.BoolVar(&cfg.trivyOffline, "trivy-offline", envTrue("TRIVY_OFFLINE"), "Skip Trivy DB updates (expects a pre-populated cache).")

	flag.BoolVar(&cfg.ecrEnabled, "ecr-enabled", envTrue("HEIMDALL_ECR_ENABLED"), "Enable the ECR credential provider (uses IRSA).")
	flag.StringVar(&cfg.ecrRegion, "ecr-region", envOrDefault("AWS_REGION", ""), "Override region for the ECR credential provider.")
	flag.BoolVar(&cfg.gcrEnabled, "gcr-enabled", true, "Enable the GCR/Artifact Registry credential provider (Google ADC / Workload Identity).")

	opts := zap.Options{Development: false, TimeEncoder: zapcore.ISO8601TimeEncoder}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	return cfg
}

func main() {
	cfg := parseFlags()
	setupLog := ctrl.Log.WithName("setup")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: cfg.metricsAddr},
		HealthProbeBindAddress: cfg.probeAddr,
		LeaderElection:         cfg.enableLeader,
		LeaderElectionID:       cfg.leaderID,
		// Pull secrets are read on demand; caching would mean watching every
		// Secret in the cluster.
		Client: client.Options{Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}}}},
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "add healthz")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "add readyz")
		os.Exit(1)
	}

	// Credential chain assembly.
	providers := []registry.CredentialProvider{}
	if cfg.ecrEnabled {
		ecr := registry.NewECRProvider()
		ecr.Region = cfg.ecrRegion
		providers = append(providers, ecr)
	}
	if cfg.gcrEnabled {
		providers = append(providers, registry.NewGCRProvider())
	}
	providers = append(providers, registry.NewPullSecretProvider(&controller.ClientSecretResolver{Client: mgr.GetClient()}))
	creds := registry.NewChain(providers...)

	// Scanner.
	trivy := scanner.NewTrivyScanner()
	trivy.CacheDir = cfg.trivyCacheDir
	trivy.Offline = cfg.trivyOffline
	trivy.Cooldown = cfg.scanCooldown

	// Alerter.
	minSev := heimdallv1alpha1.Severity(cfg.minSeverity)
	alerter := alert.NewSlackAlerter(cfg.slackWebhook, minSev)

	// Pod controller: builds the inventory.
	if err := (&controller.PodReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to set up PodReconciler")
		os.Exit(1)
	}

	// Image scan controller: scans each inventory record.
	if err := (&controller.ImageScanReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Scanner:       trivy,
		Creds:         creds,
		Alerter:       alerter,
		Interval:      cfg.scanInterval,
		ScanTimeout:   cfg.scanTimeout,
		MaxConcurrent: cfg.scanConcurrency,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to set up ImageScanReconciler")
		os.Exit(1)
	}

	setupLog.Info("starting manager",
		"scanInterval", cfg.scanInterval,
		"scanConcurrency", cfg.scanConcurrency,
		"scanCooldown", cfg.scanCooldown,
		"version", version,
		"ecrEnabled", cfg.ecrEnabled,
		"alertsEnabled", cfg.slackWebhook != "",
		"minSeverity", cfg.minSeverity,
	)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "manager exited with error")
		os.Exit(1)
	}
}

func envOrDefault(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envTrue(key string) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return false
	}
	switch v {
	case "1", "true", "TRUE", "True", "yes", "YES":
		return true
	}
	return false
}

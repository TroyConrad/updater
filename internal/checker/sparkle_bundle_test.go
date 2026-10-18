package checker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/lu-zhengda/updater/internal/app"
	"github.com/lu-zhengda/updater/internal/version"
)

// Opt-in: validate an extracted, current app against its captured Sparkle feed.
// The bundle is read through normal discovery; nothing is installed or launched.
func TestSparkleDownloadedBundle(t *testing.T) {
	dir, feedPath := os.Getenv("UPDATER_TEST_SPARKLE_DIR"), os.Getenv("UPDATER_TEST_SPARKLE_FEED")
	if dir == "" && feedPath == "" {
		t.Skip("set UPDATER_TEST_SPARKLE_DIR and UPDATER_TEST_SPARKLE_FEED to a current app directory and feed snapshot")
	}
	if dir == "" || feedPath == "" {
		t.Fatal("both the app directory and feed snapshot are required")
	}
	apps, err := app.Discover(dir)
	if err != nil || len(apps) != 1 {
		t.Fatalf("expected one discovered app, got %d: %v", len(apps), err)
	}
	a := apps[0]
	if a.Version == "" || a.Build == "" || a.FeedURL == "" {
		t.Fatalf("bundle is missing release, build, or feed metadata: %+v", a)
	}
	feed, err := os.ReadFile(feedPath)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(feed)
	}))
	defer ts.Close()
	a.FeedURL = ts.URL
	c := NewSparkleChecker(ts.Client())
	for _, renamed := range []bool{false, true} {
		candidate := *a
		if renamed {
			candidate.Name, candidate.BundleID = "Example Editor", "org.example.editor"
		}
		result, err := c.Check(context.Background(), &candidate)
		if err != nil {
			t.Fatal(err)
		}
		if result.HasUpdate || result.StaleSource || result.IsMajorUpdate || result.DownloadURL == "" {
			t.Fatalf("current bundle offered an update or failed to match its feed: %+v", result)
		}
		t.Logf("%s: short=%s build=%s latest=%s; previous short-only comparison=%v, fixed comparison=%v",
			candidate.Name, candidate.Version, candidate.Build, result.LatestVersion,
			version.IsNewer(candidate.Version, result.LatestVersion), result.HasUpdate)
	}
}

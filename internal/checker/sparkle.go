package checker

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/lu-zhengda/updater/internal/app"
	"github.com/lu-zhengda/updater/internal/architecture"
	"github.com/lu-zhengda/updater/internal/version"
)

// Sparkle RSS/appcast XML structures.
// In real-world Sparkle feeds, version info is typically on enclosure attributes,
// not child elements. We support both for maximum compatibility.
type sparkleRSS struct {
	XMLName xml.Name       `xml:"rss"`
	Channel sparkleChannel `xml:"channel"`
}

type sparkleChannel struct {
	Items []sparkleItem `xml:"item"`
}

type sparkleItem struct {
	Title              string           `xml:"title"`
	Version            string           `xml:"http://www.andymatuschak.org/xml-namespaces/sparkle version"`
	ShortVersionString string           `xml:"http://www.andymatuschak.org/xml-namespaces/sparkle shortVersionString"`
	ReleaseNotesLink   string           `xml:"http://www.andymatuschak.org/xml-namespaces/sparkle releaseNotesLink"`
	MinSystemVersion   string           `xml:"http://www.andymatuschak.org/xml-namespaces/sparkle minimumSystemVersion"`
	MaxSystemVersion   string           `xml:"http://www.andymatuschak.org/xml-namespaces/sparkle maximumSystemVersion"`
	Enclosure          sparkleEnclosure `xml:"enclosure"`
}

type sparkleEnclosure struct {
	URL                string `xml:"url,attr"`
	Length             string `xml:"length,attr"`
	Type               string `xml:"type,attr"`
	Version            string `xml:"http://www.andymatuschak.org/xml-namespaces/sparkle version,attr"`
	ShortVersionString string `xml:"http://www.andymatuschak.org/xml-namespaces/sparkle shortVersionString,attr"`
}

// buildVersion is Sparkle's machine-readable version (CFBundleVersion).
func (item sparkleItem) buildVersion() string {
	if item.Enclosure.Version != "" {
		return item.Enclosure.Version
	}
	return item.Version
}

func (item sparkleItem) displayVersion() string {
	if item.Enclosure.ShortVersionString != "" {
		return item.Enclosure.ShortVersionString
	}
	if item.ShortVersionString != "" {
		return item.ShortVersionString
	}
	return item.buildVersion()
}

// Some feeds include a build in their human-readable short version, e.g.
// "1.168.0 (88413)". Remove only that numeric suffix when comparing releases.
var sparkleBuildSuffix = regexp.MustCompile(`\s+\([0-9]+(?:\.[0-9]+)*\)$`)

func sparkleReleaseVersion(v string) string {
	return sparkleBuildSuffix.ReplaceAllString(strings.TrimSpace(v), "")
}

// SparkleChecker checks for updates via Sparkle appcast feeds.
type SparkleChecker struct {
	client *http.Client
}

// NewSparkleChecker creates a new SparkleChecker with the given HTTP client.
// If client is nil, a hardened client with a 30-second timeout is used.
func NewSparkleChecker(client *http.Client) *SparkleChecker {
	client = hardenedHTTPClient(client, 30*time.Second)
	return &SparkleChecker{client: client}
}

// Name returns the checker's display name.
func (s *SparkleChecker) Name() string {
	return "sparkle"
}

// CanCheck returns true if the app has a Sparkle feed URL.
func (s *SparkleChecker) CanCheck(a *app.App) bool {
	return a.FeedURL != ""
}

// Check fetches the Sparkle appcast feed and compares the latest version.
func (s *SparkleChecker) Check(ctx context.Context, a *app.App) (*UpdateResult, error) {
	if a.FeedURL == "" {
		return nil, fmt.Errorf("failed to check sparkle update: no feed URL for %s", a.Name)
	}
	if err := validateHTTPSURL(a.FeedURL); err != nil {
		return nil, fmt.Errorf("refusing insecure Sparkle feed for %s: %w", a.Name, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.FeedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", a.Name, err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch appcast for %s: %w", a.Name, err)
	}
	defer resp.Body.Close()
	if err := validateHTTPSURL(resp.Request.URL.String()); err != nil {
		return nil, fmt.Errorf("Sparkle feed redirected to an insecure URL for %s: %w", a.Name, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch appcast for %s: status %d", a.Name, resp.StatusCode)
	}

	body, err := readMetadataResponse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read appcast for %s: %w", a.Name, err)
	}
	var rss sparkleRSS
	if err := xml.Unmarshal(body, &rss); err != nil {
		return nil, fmt.Errorf("failed to parse appcast for %s: %w", a.Name, err)
	}

	if len(rss.Channel.Items) == 0 {
		return nil, fmt.Errorf("failed to check sparkle update: no items in appcast for %s", a.Name)
	}

	// Select the newest release compatible with the current macOS version.
	macOSVersion := getMacOSVersionFn()
	item := findBestItem(rss.Channel.Items, macOSVersion)
	if item == (sparkleItem{}) {
		return &UpdateResult{
			App: a, Source: "sparkle",
			CurrentVersion: a.Version, LatestVersion: a.Version,
		}, nil
	}

	latestVersion := item.displayVersion()
	current, latest := sparkleReleaseVersion(a.Version), sparkleReleaseVersion(latestVersion)
	major := version.IsMajorUpgrade(current, latest)
	// Sparkle compares sparkle:version with CFBundleVersion; the short version
	// is for display. Fall back to release versions only when a build is missing.
	if build := item.buildVersion(); a.Build != "" && build != "" {
		current, latest = a.Build, build
		if item.Enclosure.ShortVersionString == "" && item.ShortVersionString == "" {
			major = version.IsMajorUpgrade(current, latest)
		}
	}

	hasUpdate := version.IsNewer(current, latest)

	// Detect stale feed: if the feed's latest is older than installed,
	// the feed is likely abandoned (e.g., PDF Expert Sparkle returns v2.x for v3.x installs).
	stale := !hasUpdate && latest != "" && version.IsNewer(latest, current)

	return &UpdateResult{
		App:            a,
		Source:         "sparkle",
		CurrentVersion: a.Version,
		LatestVersion:  latestVersion,
		DownloadURL:    item.Enclosure.URL,
		ReleaseNotes:   item.ReleaseNotesLink,
		HasUpdate:      hasUpdate,
		IsMajorUpdate:  hasUpdate && major,
		StaleSource:    stale,
	}, nil
}

// findBestItem picks the most appropriate item from the feed,
// filtering by macOS compatibility and preferring the newest version.
// It returns a zero item if no release is compatible.
func findBestItem(items []sparkleItem, macOSVersion string) sparkleItem {
	var best sparkleItem
	bestScore := 0

	for _, item := range items {
		score := architecture.Score(item.Enclosure.URL, architecture.Native())
		if score == 0 {
			continue
		}
		// Skip items incompatible with current macOS
		if item.MinSystemVersion != "" && macOSVersion != "" {
			if !version.IsNewerOrEqual(item.MinSystemVersion, macOSVersion) {
				continue
			}
		}
		if item.MaxSystemVersion != "" && macOSVersion != "" {
			if version.IsNewer(item.MaxSystemVersion, macOSVersion) {
				continue
			}
		}

		// Rank by the machine-readable build, including releases with identical
		// short versions. If either item lacks a build, compare both releases
		// instead of comparing a release number with an internal build counter.
		bestVersion, v := best.buildVersion(), item.buildVersion()
		if bestVersion == "" || v == "" {
			bestVersion = sparkleReleaseVersion(best.displayVersion())
			v = sparkleReleaseVersion(item.displayVersion())
		}

		if bestVersion == "" || version.IsNewer(bestVersion, v) || v == bestVersion && score > bestScore {
			bestScore = score
			best = item
		}
	}

	return best
}

// getMacOSVersionFn returns the current macOS version (e.g., "15.3").
// It is a variable so tests can override it.
var getMacOSVersionFn = func() string {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

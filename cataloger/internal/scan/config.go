// Package scan turns an opened container root into the protocol's
// component list with Syft: the cataloger configuration, the run, and the
// mapping from Syft packages to broker components with the per-package
// flags.
package scan

import (
	"runtime/debug"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"

	// The rpm cataloger reads newer (sqlite) rpmdbs through database/sql;
	// Syft's CLI registers the same pure-Go driver.
	_ "modernc.org/sqlite"

	"github.com/kguardian-dev/kguardian/cataloger/internal/protocol"
)

// osOnlyCatalogers is the degraded profile: OS package databases and
// compiled binaries. Nothing here unpacks archives, so it needs almost no
// temp space (the rpm cataloger copies the rpmdb, a few MiB).
var osOnlyCatalogers = []string{
	"apk-db-cataloger",
	"dpkg-db-cataloger",
	"rpm-db-cataloger",
	"alpm-db-cataloger",
	"portage-cataloger",
	"go-module-binary-cataloger",
	"cargo-auditable-binary-cataloger",
	"elf-binary-package-cataloger",
	"binary-classifier-cataloger",
}

// SyftConfig is the Syft configuration for a profile. The differential
// test runs Syft's stock directory source with this same configuration,
// so the only variable between the two is the resolver.
//
//   - Catalogers: Syft's "image" set (installed software, as for a
//     container image; not lock files or manifests), or osOnlyCatalogers.
//   - Metadata only: no file digests, no file metadata or content
//     cataloging, no license text, no CPE generation.
//   - No network, ever: every remote lookup is off (and the seccomp
//     filter allows AF_UNIX sockets only).
func SyftConfig(profile string, version string) *syft.CreateSBOMConfig {
	cfg := syft.DefaultCreateSBOMConfig().
		WithTool("kguardian-cataloger", version).
		WithParallelism(1).
		WithFilesConfig(filecataloging.Config{Selection: file.NoFilesSelection}).
		WithLicenseConfig(cataloging.LicenseConfig{IncludeContent: cataloging.LicenseContentExcludeAll, Coverage: cataloging.DefaultLicenseConfig().Coverage}).
		WithDataGenerationConfig(cataloging.DataGenerationConfig{GenerateCPEs: false})

	p := pkgcataloging.DefaultConfig()
	p.Golang = p.Golang.WithSearchLocalModCacheLicenses(false).WithSearchLocalVendorLicenses(false).WithSearchRemoteLicenses(false)
	p.JavaArchive = p.JavaArchive.WithUseNetwork(false).WithUseMavenLocalRepository(false)
	p.JavaScript = p.JavaScript.WithSearchRemoteLicenses(false)
	p.Python = p.Python.WithSearchRemoteLicenses(false)
	cfg = cfg.WithPackagesConfig(p)

	sel := cataloging.NewSelectionRequest()
	if profile == protocol.ProfileOSOnly {
		sel = sel.WithDefaults(osOnlyCatalogers...)
	} else {
		sel = sel.WithDefaults(pkgcataloging.ImageTag)
	}
	// File catalogers (digests, metadata, content) are off entirely.
	sel = sel.WithRemovals(filecataloging.FileTag)
	return cfg.WithCatalogerSelection(sel)
}

// SyftVersion is the Syft module version linked into this binary.
func SyftVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/anchore/syft" {
				if d.Replace != nil {
					return d.Replace.Version
				}
				return d.Version
			}
		}
	}
	return "unknown"
}

# Releasing

How agent releases are built, signed and published, and how the signing keys
are managed. See [localport.io/docs/installation](https://localport.io/docs/installation)
for installation and [SECURITY.md](SECURITY.md) for verification.

## What a release contains

| Artifact | Where | Verified by |
|---|---|---|
| `localport` and `localport-session` binaries for linux (amd64, arm64, armv6+; glibc and musl session builds), darwin (amd64, arm64), windows (amd64) | GitHub release | `checksums.txt` |
| Windows installer (`localport-setup-<version>-windows-amd64.exe`) and zip, Authenticode-signed when SignPath is configured | GitHub release | `checksums.txt` |
| OpenWrt packages (`localport-openwrt-<package arch>.apk`) | GitHub release; feed `openwrt/<series>/<package arch>/` on `pkg.localport.io` | `checksums.txt`; the feed's `packages.adb` against the OpenWrt key |
| `checksums.txt` | GitHub release | `checksums.txt.sig` (release key) and `checksums.txt.sigstore.json` (release workflow) |
| SLSA build provenance for every file | GitHub attestations | `gh attestation verify` |
| SPDX SBOM (`localport.spdx.json`) | GitHub release | `checksums.txt` |
| deb, rpm and apk packages | `pkg.localport.io` | apt, dnf, apk against the repository keys |
| Container image, amd64, arm64, arm/v7 | `ghcr.io/localport/agent` | cosign (release workflow), build provenance |
| Homebrew formula, Scoop manifest, winget manifest | their repositories | SHA-256 pinned from the signed `checksums.txt` |

Prereleases (`vX.Y.Z-rc.N`) publish the GitHub release and a versioned image
only, without OpenWrt packages (OpenWrt versions are `X.Y.Z` only). Package
repositories, the OpenWrt feed and package managers carry stable releases.

## Keys

| Key | Held in | Signs |
|---|---|---|
| Release key, `ecdsa-sha2-nistp256` | the maintainer's hardware (Secure Enclave), never exported | `checksums.txt`, by hand for each release |
| Repository key, OpenPGP RSA 4096 | the `release` environment secret `REPO_GPG_PRIVATE_KEY` | apt `InRelease`/`Release.gpg`, rpm packages, `repomd.xml` |
| apk key, RSA 4096 | the `release` environment secret `APK_PRIVATE_KEY` | apk packages, `APKINDEX.tar.gz` |
| OpenWrt key, ECDSA P-256 | the `release` environment secret `OPENWRT_PRIVATE_KEY` | each OpenWrt feed's `packages.adb` (the packages themselves are unsigned, as in OpenWrt's own feeds) |
| Authenticode certificate | SignPath Foundation; the repository secret `SIGNPATH_API_TOKEN` and the variables `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG`, `SIGNPATH_SIGNING_POLICY_SLUG` | the Windows executables, uninstaller and installer |
| Workflow identity (Sigstore, keyless) | GitHub OIDC, no stored key | `checksums.txt.sigstore.json`, the image, build provenance |

Public halves are committed:

- `release/signing-key.pub` and `release/allowed_signers`: the release key.
- `release/keys/localport-archive-keyring.gpg` (binary) and
  `release/keys/RPM-GPG-KEY-localport` (armored): the repository key.
- `release/keys/<name>.rsa.pub`: the apk key. The file name is the name apk
  matches signatures against.
- `release/keys/localport-openwrt.pem`: the OpenWrt key. Publish copies it to
  `openwrt/` in the repository; routers install it in `/etc/apk/keys/`.
  `.gitignore` ignores `*.pem` except under `release/keys/`.
- `release/keys/VERSION`: the version of the `localport-archive-keyring`
  package, as `YYYY.MM.DD`.

The install scripts embed these public keys. A key change requires new install
scripts.

## Cutting a release

1. Confirm `main` is green, then tag the commit and push the tag:

   ```sh
   git tag -s vX.Y.Z -m vX.Y.Z
   git push origin vX.Y.Z
   ```

2. The tag starts the build jobs:
   - **Check tag** accepts `vX.Y.Z` and `vX.Y.Z-PRERELEASE` only.
   - **Session builds** build `localport-session` for every platform and the
     signed darwin binaries; **OpenWrt** builds one package per package arch
     with the pinned SDK (stable tags only).
   - **Build draft** builds the rest of the release set and the SBOM.
   - **Windows packages** builds the installer and zip. With
     `SIGNPATH_PROJECT_SLUG` set, SignPath signs in two submissions, each
     approved in SignPath: the executables and uninstaller, then the
     installer.
   - **Draft release** writes `checksums.txt`, attests provenance, signs
     `checksums.txt` with Sigstore and creates the draft release.

   Only **Windows packages** holds a secret (`SIGNPATH_API_TOKEN`).

3. Sign the draft on the machine that holds the release key:

   ```sh
   make release-sign TAG=vX.Y.Z
   ```

   This downloads the draft, checks every file's provenance against this
   repository's release workflow and the tag, checks every hash, signs
   `checksums.txt` (confirm on the key), verifies the signature against
   `release/allowed_signers` and uploads `checksums.txt.sig`.

4. Approve the **Publish** job in the `release` environment. It verifies
   `checksums.txt.sig` before anything else, then:
   - builds and signs the packages, merges them into the published repository,
     rebuilds and signs the indexes, and adds the OpenWrt packages to the feed
     with a signed `packages.adb` per package arch;
   - installs from the new repository on Debian, Ubuntu, Rocky Linux, Amazon
     Linux, Fedora and Alpine, and stops if any install fails;
   - publishes the repository, then the image, then the GitHub release;
   - opens pull requests on `localport/homebrew-tap` and
     `localport/scoop-bucket`.

   The **winget** job then opens the `microsoft/winget-pkgs` pull request with
   [Komac](https://github.com/russellbanks/Komac), once the repository
   variable `WINGET_IDENTIFIER` is set. It runs in the `winget` environment,
   which holds only `WINGET_TOKEN`, and its `GITHUB_TOKEN` has no permissions.

5. Merge the Homebrew and Scoop pull requests once their checks pass.

A failed publish or winget job can be re-run. Komac skips a version that
already has an open pull request.

`make release-dryrun` runs the Linux part of steps 2 and 4 with throwaway
keys and publishes nothing. `make dist` needs the `localport-session` and
darwin binaries in `bin/` first; only the session builds make them. A local
`make build-session-linux` sends only tracked files to Docker
(`scripts/release/tracked-context.sh`), so `git add` a new file before a
local session build. The **CI** workflow runs the session builds and the dry run on every push to
`main` and every pull request. The **Packaging** workflow builds the x86_64
OpenWrt package on every push to `main` and on every pull request that
changes the pipeline.

## Key rotation

### Release key

- **Lost** (hardware replaced, key not exposed): generate a new key, add its
  line to `release/allowed_signers` beside the old one, replace
  `release/signing-key.pub`, and ship installers with the new file. Earlier
  releases keep verifying against the old line.
- **Compromised**: generate a new key and remove the old line. For every
  release still in use, run `gh attestation verify` on its files, then sign
  its `checksums.txt` with the new key and replace `checksums.txt.sig`. Ship
  installers with the new `allowed_signers` and announce the rotation.

`allowed_signers` sets no `valid-after` or `valid-before`. OpenSSH before 8.7
rejects them, and they are checked at verification time.

### Repository key

1. Generate the new key and add its public half to
   `release/keys/localport-archive-keyring.gpg` and
   `release/keys/RPM-GPG-KEY-localport` alongside the old one. Bump
   `release/keys/VERSION`.
2. Release. The keyring package delivers both keys through apt and dnf.
3. After the keyring has been out for at least one release cycle, switch
   `REPO_GPG_PRIVATE_KEY` to the new key and release again.
4. Remove the old public key in a later release.

A compromised repository key skips the overlap: switch the secret, publish a
keyring holding only the new key, and announce that systems must fetch it
from `pkg.localport.io` again.

### apk key

apk has no keyring package. Ship install scripts with the new `<name>.rsa.pub`
first. Then switch `APK_PRIVATE_KEY`, replace the file in `release/keys`, and
release. Existing Alpine systems fetch the new public key
as documented.

### OpenWrt key

The feed has no keyring package either. Publish the new public key beside the
old one under `openwrt/` and document it first, then switch
`OPENWRT_PRIVATE_KEY`, replace `release/keys/localport-openwrt.pem`, and
release. Routers trust the new index once they install the new key in
`/etc/apk/keys/`.

Generate a key with `openssl ecparam -name prime256v1 -genkey -noout` and its
public half with `openssl ec -pubout`.

## Maintenance

- Actions are pinned by commit SHA and updated by Dependabot, as are Go
  modules and the image's base.
- Dependabot proposes a version update 7 days after its release. Security
  updates are not delayed.
- Updated by hand: the Debian and Alpine images in the `Makefile`
  (`DEBIAN_IMAGE`, `ALPINE_IMAGE`, pinned by digest), the distributions in
  `scripts/release/repo-test.sh`, the cosign version in `release.yml`, Komac
  (`KOMAC_VERSION`, `KOMAC_SHA256` in `release.yml`), NSIS (`NSIS_VERSION`,
  `NSIS_ZIP_SHA256` in `release.yml`), the OpenWrt SDKs (`release` and the
  per-arch SHA-256 list in `packaging/openwrt/sdk.sh`; the feed directory
  follows the release series), the binfmt and BuildKit images the session and
  image builds use (digests in `session.yml`, `session-builder.yml` and
  `release.yml`), and cargo-deny (`CARGO_DENY_VERSION`, `CARGO_DENY_SHA256` in
  `ci.yml`).

### Session builder images

The Linux `localport-session` builds run on toolchain images built from
`packaging/session/builder.Dockerfile`: gcc, the PAM headers, binutils and git
at exact package versions, without Go. The **Session builder** workflow
(`session-builder.yml`) builds each stage, pushes it to
`ghcr.io/localport/session-builder:<stage>` with an SBOM and build provenance,
and signs it with cosign (keyless, from `main`). It runs on `main` only: on a
push that changes the builder file or the workflow, or by hand. The GHCR
package is public, so release and pull request builds pull it without
credentials.

`packaging/session/Dockerfile` names each image by digest and copies Go from
the official `golang` images. Before any build, `session.yml` runs
`cosign verify` on every builder reference in that file against the identity
`https://github.com/localport/agent/.github/workflows/session-builder.yml@refs/heads/main`;
an unsigned or foreign image fails the session builds.

To update a toolchain (a package version, or the AlmaLinux or Alpine base):

1. Change `packaging/session/builder.Dockerfile` and merge it to `main`.
   Alpine keeps one build per package, so a pinned `-rN` that Alpine has
   replaced fails this build until it is updated; release builds keep using
   the pinned image meanwhile.
2. Wait for the **Session builder** run on `main`; its job summary lists the
   new digest of each stage.
3. Replace the digests in `packaging/session/Dockerfile` with those digests,
   and let the **CI** workflow's session builds and dry run pass before a
   release.

The cosign version in `session.yml` and `session-builder.yml` is updated by
hand, with the one in `release.yml`.

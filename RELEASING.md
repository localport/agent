# Releasing

How agent releases are built, signed and published, and how the signing keys
are managed. See [localport.io/docs/installation](https://localport.io/docs/installation)
for installation and [SECURITY.md](SECURITY.md) for verification.

## What a release contains

| Artifact | Where | Verified by |
|---|---|---|
| Binaries for linux (amd64, arm64, armv6+), darwin (amd64, arm64), windows (amd64) | GitHub release | `checksums.txt` |
| `checksums.txt` | GitHub release | `checksums.txt.sig` (release key) and `checksums.txt.sigstore.json` (release workflow) |
| SLSA build provenance for every file | GitHub attestations | `gh attestation verify` |
| SPDX SBOM (`localport.spdx.json`) | GitHub release | `checksums.txt` |
| deb, rpm and apk packages | `pkg.localport.io` | apt, dnf, apk against the repository keys |
| Container image, amd64, arm64, arm/v7 | `ghcr.io/localport/agent` | cosign (release workflow), build provenance |
| Homebrew formula, Scoop manifest, winget manifest | their repositories | SHA-256 pinned from the signed `checksums.txt` |

Prereleases (`vX.Y.Z-rc.N`) publish the GitHub release and a versioned image
only. Package repositories and package managers carry stable releases.

## Keys

| Key | Held in | Signs |
|---|---|---|
| Release key, `ecdsa-sha2-nistp256` | the maintainer's hardware (Secure Enclave), never exported | `checksums.txt`, by hand for each release |
| Repository key, OpenPGP RSA 4096 | the `release` environment secret `REPO_GPG_PRIVATE_KEY` | apt `InRelease`/`Release.gpg`, rpm packages, `repomd.xml` |
| apk key, RSA 4096 | the `release` environment secret `APK_PRIVATE_KEY` | apk packages, `APKINDEX.tar.gz` |
| Workflow identity (Sigstore, keyless) | GitHub OIDC, no stored key | `checksums.txt.sigstore.json`, the image, build provenance |

Public halves are committed:

- `release/signing-key.pub` and `release/allowed_signers`: the release key.
- `release/keys/localport-archive-keyring.gpg` (binary) and
  `release/keys/RPM-GPG-KEY-localport` (armored): the repository key.
- `release/keys/<name>.rsa.pub`: the apk key. The file name is the name apk
  matches signatures against.
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

2. The **Build draft** job builds the release set, generates the SBOM,
   attests provenance, signs `checksums.txt` with Sigstore and creates a draft
   release. It holds no secret.

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
     rebuilds and signs the indexes;
   - installs from the new repository on Debian, Ubuntu, Rocky Linux, Fedora
     and Alpine, and stops if any install fails;
   - publishes the repository, then the image, then the GitHub release;
   - opens pull requests on `localport/homebrew-tap`, `localport/scoop-bucket`
     and, once `WINGET_IDENTIFIER` is set, `microsoft/winget-pkgs`.

5. Merge the Homebrew and Scoop pull requests once their checks pass.

A failed publish job can be re-run. Afterwards, check `microsoft/winget-pkgs`
for a duplicate pull request.

`make release-dryrun` runs steps 2 and 4 locally with throwaway keys and
publishes nothing. The **Packaging** workflow runs it on every change to the
pipeline.

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

## Maintenance

- Actions are pinned by commit SHA and updated by Dependabot, as are Go
  modules and the image's base.
- The Debian and Alpine images in the `Makefile` (`DEBIAN_IMAGE`,
  `ALPINE_IMAGE`) are pinned by digest and updated by hand.

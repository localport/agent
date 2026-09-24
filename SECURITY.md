# Security policy

## Reporting a vulnerability

Report vulnerabilities privately, by either route:

- [Open a private advisory](https://github.com/localport/agent/security/advisories/new) on this repository.
- Email [security@localport.io](mailto:security@localport.io).

Do not open a public issue for a vulnerability.

Include the affected version (`localport version`), the operating system, the steps to reproduce, and the impact you observed. Reports about the Localport service rather than this agent (the edge network, the dashboard, the API) go to the same address.

## Supported versions

Security fixes are released as a new version of the agent. Only the latest release is supported. Upgrade to it before reporting.

## Verifying a release

Every release is built by the [release workflow](.github/workflows/release.yml) from a tagged commit and published with:

- `checksums.txt`, listing the SHA-256 of every release file;
- `checksums.txt.sig`, an SSH signature over `checksums.txt` by the release key in [`release/allowed_signers`](release/allowed_signers);
- `checksums.txt.sigstore.json`, a Sigstore signature over `checksums.txt` by the release workflow;
- SLSA build provenance for every file, and an SPDX SBOM.

To check a downloaded release with the release key (OpenSSH 8.1 or later):

```sh
ssh-keygen -Y verify -f allowed_signers -I release@localport.io \
  -n localport-release -s checksums.txt.sig < checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

To check a file's build provenance with the GitHub CLI:

```sh
gh attestation verify localport-linux-amd64 --repo localport/agent \
  --signer-workflow localport/agent/.github/workflows/release.yml
```

To check the container image (cosign 3.1.3 or later):

```sh
cosign verify ghcr.io/localport/agent:<version> \
  --certificate-identity-regexp '^https://github\.com/localport/agent/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Packages from `pkg.localport.io` are verified by apt, dnf and apk against the repository keys in [`release/keys`](release/keys). [RELEASING.md](RELEASING.md) describes the full process and every key.

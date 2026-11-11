"""Validates rendered package manager manifests against their official schemas.

    python3 -I validate_manifests.py <rendered-dir> <winget-schema-dir> <scoop-schema.json>

<rendered-dir> is the output of `scripts/release/manifests.sh render`:
localport.json (Scoop) and winget/*.yaml. Each winget file is checked against
manifest.<ManifestType>.1.28.0.json from <winget-schema-dir>. Exits non-zero
and names every violation when a manifest does not validate.
"""

import json
import pathlib
import sys

import jsonschema
import yaml


def errors(instance, schema_path):
    schema = json.loads(pathlib.Path(schema_path).read_text(encoding="utf-8"))
    validator = jsonschema.validators.validator_for(schema)(schema)
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in validator.iter_errors(instance)]


def main(rendered, winget_schemas, scoop_schema):
    failed = []
    rendered = pathlib.Path(rendered)
    scoop = rendered / "localport.json"
    failed += [f"{scoop.name}: {e}" for e in errors(json.loads(scoop.read_text(encoding="utf-8")), scoop_schema)]
    winget = sorted((rendered / "winget").glob("*.yaml"))
    if len(winget) != 3:
        failed.append(f"want 3 winget manifests, found {len(winget)}")
    for path in winget:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        schema = pathlib.Path(winget_schemas) / f"manifest.{doc['ManifestType']}.{doc['ManifestVersion']}.json"
        failed += [f"{path.name}: {e}" for e in errors(doc, schema)]
    for line in failed:
        print(line, file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))

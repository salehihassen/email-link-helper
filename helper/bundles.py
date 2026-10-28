"""Build the same credential-free browser bundles for downloads and CI."""
import io
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent/'extension'


def build(browser):
    if browser not in ['chrome', 'firefox']:
        raise ValueError('Unknown browser')
    manifest = json.loads((ROOT/f'manifest.{browser}.json').read_text())
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('manifest.json', json.dumps(manifest, indent=2))
        for path in sorted(ROOT.iterdir()):
            if path.suffix in ['.js', '.html', '.css', '.svg']:
                archive.write(path, path.name)
    return data.getvalue()

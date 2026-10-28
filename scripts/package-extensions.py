#!/usr/bin/env python3
"""Create and sanity-check installable bundles without credentials or a server."""
import io
import json
from pathlib import Path
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from helper.bundles import build

versions = set()
for browser in ['chrome', 'firefox']:
    payload = build(browser)
    target = Path('dist')/browser
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        manifest = json.loads(archive.read('manifest.json'))
        assert manifest['manifest_version'] == 3
        assert set(manifest['permissions']) == {'storage', 'alarms'}
        assert not manifest.get('host_permissions') and not manifest.get('content_scripts')
        background = 'service_worker' if browser == 'chrome' else 'scripts'
        assert background in manifest['background']
        assert {'background.js', 'options.js', 'popup.js', 'options.html', 'popup.html', 'style.css'} <= set(archive.namelist())
        assert all(Path(name).name == name for name in archive.namelist())
        versions.add(manifest['version'])
        archive.extractall(target)
    (Path('dist')/f'email-link-helper-{browser}.zip').write_bytes(payload)
assert len(versions) == 1, 'Browser bundle versions must match'
print('Chrome and Firefox bundles built and checked.')

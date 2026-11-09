#!/usr/bin/env python3
"""Keep public PR checks unprivileged and independent of deployment secrets."""
from pathlib import Path
import re
import yaml

path = Path('.github/workflows/checks.yml')
text = path.read_text()
workflow = yaml.load(text, Loader=yaml.BaseLoader)
assert set(workflow['on']) == {'push', 'pull_request', 'workflow_dispatch'}
assert workflow['on']['push']['branches'] == ['main']
assert workflow['permissions'] == {'contents': 'read'}
assert 'secrets.' not in text
for job in workflow['jobs'].values():
    assert job['runs-on'] == 'ubuntu-latest'
    for step in job['steps']:
        if 'uses' in step:
            assert re.fullmatch(r'actions/[a-z-]+@[a-f0-9]{40}', step['uses'])
        if step.get('uses', '').startswith('actions/checkout@'):
            assert step['with']['persist-credentials'] == 'false'
jobs = workflow['jobs']
# Lint must gate the build, but share nothing with it beyond pass/fail.
assert jobs['sanity']['needs'] == 'lint-extensions'
assert 'outputs' not in jobs['lint-extensions']
assert 'upload-artifact' not in text and 'download-artifact' not in text
print('CI policy: public PR trigger, hosted runner, read-only token, pinned actions, no deployment secrets, isolated lint gate.')

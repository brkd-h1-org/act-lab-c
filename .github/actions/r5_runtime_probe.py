#!/usr/bin/env python3
"""Probe extra Actions services with the job runtime token + OIDC. Redact secrets."""
import base64, json, os, re, urllib.error, urllib.request

env_path = os.environ.get("RUNNER_TEMP", "/tmp") + "/runtime_env.json"
env = {}
if os.path.exists(env_path):
    env = json.load(open(env_path))

TOKEN = env.get("ACTIONS_RUNTIME_TOKEN") or os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
IDURL = env.get("ACTIONS_ID_TOKEN_REQUEST_URL") or os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
RESULTS = env.get("ACTIONS_RESULTS_URL") or os.environ.get("ACTIONS_RESULTS_URL", "https://results-receiver.actions.githubusercontent.com/")
CACHE = env.get("ACTIONS_CACHE_URL") or os.environ.get("ACTIONS_CACHE_URL", "")
RUNTIME = env.get("ACTIONS_RUNTIME_URL") or os.environ.get("ACTIONS_RUNTIME_URL", "")
GH = os.environ.get("GITHUB_TOKEN", "")

SECRET_RE = re.compile(r"(sig=|skoid=|sktid=)[^&\"\\s]*")
JWTISH = re.compile(r"eyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}")
GHTOK = re.compile(r"gh[psoruat]_[A-Za-z0-9]{20,}|v1\\.[0-9a-f]{40}")


def redact(s):
    s = GHTOK.sub("<GHTOK>", s)
    s = JWTISH.sub("<JWT>", s)
    return SECRET_RE.sub(r"\\1<RED>", s)


def claims(tok):
    p = tok.split(".")[1]
    p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))


def call(label, method, url, token=None, body=None, extra=None, show=350):
    h = {"User-Agent": "r5-runtime-probe/1.0", "Accept": "application/json"}
    if extra:
        h.update(extra)
    if token:
        h["Authorization"] = "Bearer " + token
    data = None
    if isinstance(body, (dict, list)):
        data = json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            st, txt = r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        st, txt = e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        st, txt = -1, repr(e)
    print("%-42s -> %s %s" % (label, st, redact(txt)[:show].replace("\\n", " ")))
    return st, txt


print("TOKEN present", bool(TOKEN), "len", len(TOKEN or ""))
print("IDURL", IDURL)
print("RESULTS", RESULTS, "CACHE", CACHE, "RUNTIME", RUNTIME)
if TOKEN:
    c = claims(TOKEN)
    print("runtime claims keys", sorted(c.keys()))
    print("aud", c.get("aud"), "iss", c.get("iss"), "scp", c.get("scp"))
    print("repo", c.get("repository_id"), "owner", c.get("repository_owner_id"))

# extra services
if TOKEN:
    call("broker-root", "GET", "https://broker.actions.githubusercontent.com/", TOKEN)
    call("broker-health", "GET", "https://broker.actions.githubusercontent.com/health", TOKEN)
    call("broker-v2-messages", "GET", "https://broker.actions.githubusercontent.com/_apis/v2/messages", TOKEN)
    call("setup-tools", "GET", "https://setup-tools.actions.githubusercontent.com/", TOKEN)
    call("setup-tools-status", "GET", "https://setup-tools.actions.githubusercontent.com/status", TOKEN)
    call("launch-root", "GET", "https://launch.actions.githubusercontent.com/", TOKEN)
    call("launch-health", "GET", "https://launch.actions.githubusercontent.com/health", TOKEN)
    call("vstoken-health", "GET", "https://vstoken.actions.githubusercontent.com/_apis/health", TOKEN)
    call("tokenghub-health", "GET", "https://tokenghub.actions.githubusercontent.com/_apis/health", TOKEN)
    call("token-actions-oidc", "GET", "https://token.actions.githubusercontent.com/.well-known/openid-configuration", TOKEN)
    call("results-health", "GET", RESULTS.rstrip("/") + "/health", TOKEN)
    # GenericRead-looking methods
    if IDURL:
        base = IDURL.split("/idtoken/")[0].rstrip("/") + "/"
        call("runsvc-root", "GET", base, TOKEN)
        call("runsvc-health", "GET", base + "health", TOKEN)
        call("runsvc-acquire-empty", "POST", base + "acquirejob", TOKEN, {"jobMessageId": "", "runnerOS": "linux"})
    # results receiver undeclared methods
    rr = RESULTS.rstrip("/")
    for m in [
        "ArtifactService/GetArtifact",
        "ArtifactService/GetSignedArtifactURL",
        "CacheService/GetCacheEntryDownloadURL",
        "CacheService/CreateCacheEntry",
        "Receiver/GetJobLogsSignedBlobURL",
    ]:
        call("rr-" + m.split("/")[-1], "POST", rr + "/twirp/github.actions.results.api.v1." + m, TOKEN, {})

# OIDC mint + github-operated consumers
if IDURL and TOKEN:
    for aud in ["https://github.com/brkd-h1", "https://ghcr.io", "npm", "https://api.github.com", "sts.amazonaws.com", "nobody"]:
        url = IDURL + (("&" if "?" in IDURL else "?") + "audience=" + urllib.request.quote(aud) if "audience=" not in IDURL else "")
        # IDURL already has query; append audience
        if "audience=" in IDURL:
            sep = IDURL
        else:
            sep = IDURL + ("&" if "?" in IDURL else "?") + "audience=" + urllib.request.quote(aud)
        st, txt = call("oidc-aud-" + aud[:24], "GET", sep, TOKEN)
        if st == 200:
            try:
                tok = json.loads(txt).get("value") or json.loads(txt).get("token")
                if tok:
                    cl = claims(tok)
                    print("   oidc sub=", cl.get("sub"), "aud=", cl.get("aud"), "job_workflow_ref=", cl.get("job_workflow_ref"))
                    # try ghcr
                    if aud == "https://ghcr.io":
                        call("ghcr-token", "GET", "https://ghcr.io/token?service=ghcr.io&scope=repository:brkd-h1/act-lab-a:pull", tok)
                        call("ghcr-token-other", "GET", "https://ghcr.io/token?service=ghcr.io&scope=repository:actions/checkout:pull", tok)
                    if aud == "https://api.github.com":
                        call("api-with-oidc", "GET", "https://api.github.com/user", tok)
                        call("api-repos-oidc", "GET", "https://api.github.com/repos/brkd-h1/act-lab-a", tok)
            except Exception as e:
                print("   parse oidc", e)

# GITHUB_TOKEN attestations / packages
if GH:
    repo = os.environ.get("GITHUB_REPOSITORY", "brkd-h1/act-lab-a")
    call("gh-attestations", "GET", f"https://api.github.com/repos/{repo}/attestations", GH,
         extra={"Accept": "application/vnd.github+json"})
    call("gh-packages", "GET", f"https://api.github.com/users/brkd-h1/packages?package_type=container", GH,
         extra={"Accept": "application/vnd.github+json"})
    call("gh-org-packages", "GET", "https://api.github.com/orgs/brkd-h1-org/packages?package_type=container", GH,
         extra={"Accept": "application/vnd.github+json"})

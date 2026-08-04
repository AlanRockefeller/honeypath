"""Canary catalog: what Honeypath plants, where, and with what content.

Content rules (enforced by tests, see tests/test_catalog.py):

* Every canary is internally, obviously fake.  No valid private keys, no
  valid BIP-39 seed phrases, no real tokens, no funded wallets.
* Any host referenced by a canary lives under the reserved ``.invalid`` TLD
  (RFC 2606), so a tool that actually consumes one of these files cannot
  reach a real endpoint.
* Files that real tools actively consume are marked ``active-config`` and
  are written so that they add a *scoped* fake credential rather than
  overriding a default.  A canary ``.npmrc`` must not repoint ``npm`` at a
  dead registry; it declares a token for a registry nobody uses.
* Entries under ``.ssh/`` are activation-gated (§5.3): ordinary
  ``create-canaries`` never creates them.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import safe_write
from .target_user import TargetUserContext

# Reserved TLD — guaranteed never to resolve.
CANARY_HOST = "honeypath-canary.invalid"

INTRUSIVENESS_LOW = "low"
INTRUSIVENESS_ACTIVE = "active-config"
INTRUSIVENESS_HIGH = "high"

# --------------------------------------------------------------------------
# Categories
# --------------------------------------------------------------------------
# Every entry is audited into exactly one of these.  The category, not the
# intrusiveness label, decides whether ordinary `plan` / `create-canaries`
# will touch a path.
#
# A canary stays in CATEGORY_SAFE only when it adds an *isolated* credential —
# keyed by a reserved ``.invalid`` host, a named profile, or a custom option
# group — without changing the tool's default endpoint, default profile,
# current context, token cache or authentication chain.  Anything that
# occupies a default authentication path, or that a tool consults on every
# invocation, is CATEGORY_ACTIVE and requires --include-active-config.

CATEGORY_SAFE = "safe-default"  # created by default
CATEGORY_ACTIVE = "active-config"  # behaviour-changing; --include-active-config
CATEGORY_WATCH = "watch-only"  # never created, only watched
CATEGORY_SSH = "ssh-gated"  # only via setup-ssh-canary --activate
CATEGORY_CRYPTO = "crypto-opt-in"  # only via --include-crypto

ALL_CATEGORIES = (
    CATEGORY_SAFE,
    CATEGORY_ACTIVE,
    CATEGORY_WATCH,
    CATEGORY_SSH,
    CATEGORY_CRYPTO,
)

ACTIVE_CONFIG_EXCLUDED_NOTE = (
    "Active configuration canaries excluded; pass --include-active-config to "
    "review and enable them."
)

ACTIVE_CONFIG_WARNING = [
    "!!  --include-active-config is enabled.",
    "!!  These files occupy paths that real tools read on every invocation:",
    "!!  a default credential location, token cache, current context or sole",
    "!!  configuration file. Creating them MAY AFFECT LEGITIMATE COMMANDS —",
    "!!  kubectl, gcloud, az, dbt, gh, doctl and huggingface-cli in particular.",
    "!!  Honeypath still never overwrites an existing file, so this only",
    "!!  applies where you have no such configuration today.",
]

PLATFORM_LINUX = "linux"
PLATFORM_WINDOWS = "windows"
PLATFORM_MACOS = "macos"

PROFILE_PREFIX = {
    PLATFORM_LINUX: "linux",
    PLATFORM_WINDOWS: "wsl-windows",
    PLATFORM_MACOS: "macos",
}

BASE_PROFILES = ("developer", "supply-chain", "crypto", "browser-noisy")

_FAKE_KEY_WARNING = (
    "HONEYPATH CANARY KEY - THIS IS NOT A PRIVATE KEY. "
    "It contains no key material of any kind. If you are reading this, "
    "something read a Honeypath canary file. "
)


def _fake_key_blob(lines: int = 14, width: int = 70) -> str:
    """A base64 blob that *looks* like key material but decodes to a warning."""
    payload = (_FAKE_KEY_WARNING * 40).encode("ascii")
    encoded = base64.b64encode(payload).decode("ascii")
    wanted = lines * width
    encoded = (encoded * ((wanted // len(encoded)) + 1))[:wanted]
    return "\n".join(encoded[i : i + width] for i in range(0, wanted, width))


@dataclass(frozen=True)
class CanaryEntry:
    """One catalog entry."""

    key: str
    relative_path: str
    kind: str
    severity: str
    base_profile: str
    platform: str
    intrusiveness: str
    content: str = ""
    mode: int = 0o600
    # Watch/report-only entries (browser data) are never created by Honeypath.
    creatable: bool = True
    # Marks entries that are only planted by `setup-ssh-canary --activate`.
    ssh_gated: bool = field(default=False)
    # Audited category; see the CATEGORY_* constants.
    category: str = CATEGORY_SAFE

    @property
    def profile(self) -> str:
        return f"{PROFILE_PREFIX[self.platform]}-{self.base_profile}"

    @property
    def is_active_config(self) -> bool:
        return self.category == CATEGORY_ACTIVE

    @property
    def is_glob(self) -> bool:
        return "*" in self.relative_path or "?" in self.relative_path

    def path_for(self, home: Path) -> Path:
        return home / self.relative_path


def _under_ssh(relative_path: str) -> bool:
    parts = Path(relative_path).parts
    return ".ssh" in parts


# --------------------------------------------------------------------------
# Content templates
# --------------------------------------------------------------------------

_HEADER = "Honeypath canary file - fake credentials, safe to delete."


# The AWS profile the canary declares.  It is deliberately NOT `[default]`:
# a `[default]` profile becomes the credential the AWS SDK and CLI pick up with
# no arguments at all, which would hand fake keys to every legitimate `aws`
# invocation on the machine.  A named profile is only ever used by someone who
# asks for it with --profile or AWS_PROFILE, so it changes nothing, while a
# credential scraper reading ~/.aws/credentials still finds the material.
AWS_CANARY_PROFILE = "honeypath-canary"


def aws_credentials_content(canarytoken: dict | None = None) -> str:
    """Fake AWS credentials, optionally carrying user-supplied Canarytoken keys.

    Honeypath never generates Canarytoken material; it only splices in what
    the user supplies via --canarytoken-aws-file.
    """
    if canarytoken:
        key_id = canarytoken["aws_access_key_id"]
        secret = canarytoken["aws_secret_access_key"]
        note = "# Canarytokens-backed credentials supplied by the operator."
    else:
        key_id = "AKIAHONEYPATHCANARY0"
        secret = "hpFAKEhpFAKEhpFAKEhpFAKEhpFAKEhpFAKEhpFA"
        note = f"# {_HEADER}"
    return (
        f"{note}\n"
        "# Named profile on purpose: a [default] profile would become the\n"
        "# credential every unqualified `aws` command uses.\n"
        f"[{AWS_CANARY_PROFILE}]\n"
        f"aws_access_key_id = {key_id}\n"
        f"aws_secret_access_key = {secret}\n"
        "region = us-east-1\n"
    )


# The PEM block itself is left looking authentic (a scraper that grabs it gets
# something plausible), but the base64 decodes to a warning and a plain-text
# footer makes the file self-identifying to a human.
_SSH_PRIVATE_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    f"{_fake_key_blob()}\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
    "# HONEYPATH CANARY - not a key. Reading this file raises an alert.\n"
)

# Deliberately syntactically invalid, per §8.6 step 5: any process that still
# reads ~/.ssh/config directly (cron jobs, IDEs, hardcoded paths) must fail
# loudly instead of silently being handed canary keys.
_SSH_CANARY_CONFIG = f"""\
### {_HEADER}
### This file is INTENTIONALLY INVALID.
###
### Your real SSH configuration lives in
###   ~/.local/share/honeypath/real-ssh/config
### and is used automatically by the Honeypath ssh/scp/sftp wrappers in ~/bin.
###
### If you are seeing an OpenSSH parse error pointing at this file, some
### program invoked /usr/bin/ssh directly instead of the wrapper. Fix that
### program's PATH, or run: honeypath.py restore-ssh-canary
###
!!! HONEYPATH CANARY - NOT A VALID SSH CONFIG !!!
Host ***honeypath-canary***
    ThisIsNotAnOpenSSHKeyword yes
"""

_SSH_KNOWN_HOSTS = f"""\
# {_HEADER}
gitlab.{CANARY_HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHONEYPATHCANARYnotArealHostKey00000
build.{CANARY_HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHONEYPATHCANARYnotArealHostKey11111
"""

_NPMRC = f"""\
; {_HEADER}
; Scoped on purpose: this must never repoint npm at a dead registry.
@honeypath-canary:registry=https://registry.{CANARY_HOST}/
//registry.{CANARY_HOST}/:_authToken=npm_HoneypathCanaryFAKEtoken000000000000
"""

# No `[distutils] index-servers` block: that key redefines the set of servers
# twine and `setup.py upload` know about, which is a behaviour change. A bare
# named repository section is inert — nothing reads it unless asked for by name
# with `-r honeypath-canary` — while still looking exactly like a stolen PyPI
# token to a scraper.
_PYPIRC = f"""\
# {_HEADER}
# Scoped on purpose: no [distutils] index-servers block, so twine's default
# upload target is untouched.
[honeypath-canary]
repository = https://upload.{CANARY_HOST}/legacy/
username = __token__
password = pypi-HoneypathCanaryFAKEtokenDoNotUse000000
"""

_CARGO_CREDENTIALS = f"""\
# {_HEADER}
[registries.honeypath-canary]
token = "cioHoneypathCanaryFAKEtoken00000000"
"""

_PGPASS = f"""\
# {_HEADER}
db.{CANARY_HOST}:5432:canarydb:canaryuser:hpFAKEpgpassPassword000
"""

# A custom option group, NOT [client] — a [client] block would change the
# behaviour of every real mysql invocation on the machine.
_MY_CNF = f"""\
# {_HEADER}
[clienthoneypathcanary]
host = mysql.{CANARY_HOST}
user = honeypath_canary
password = hpFAKEmysqlPassword000
"""

_DOCKER_CONFIG = (
    json.dumps(
        {
            "__honeypath": _HEADER,
            "auths": {
                f"registry.{CANARY_HOST}": {
                    # base64("honeypath-canary:hpFAKEdockerPassword000")
                    "auth": "aG9uZXlwYXRoLWNhbmFyeTpocEZBS0Vkb2NrZXJQYXNzd29yZDAwMA==",
                    "email": f"canary@{CANARY_HOST}",
                }
            },
        },
        indent=2,
    )
    + "\n"
)

# No `current-context` key.  Setting one would make kubectl select the fake
# cluster for every unqualified command.  Without it kubectl reports that no
# context is set, which is the same outcome as having no kubeconfig at all.
# The file is still CATEGORY_ACTIVE: ~/.kube/config is kubectl's default
# configuration path and its mere presence changes kubectl's behaviour.
_KUBE_CONFIG = f"""\
# {_HEADER}
# No current-context on purpose: kubectl must not select this cluster.
apiVersion: v1
kind: Config
clusters:
- name: honeypath-canary
  cluster:
    server: https://k8s.{CANARY_HOST}:6443
    insecure-skip-tls-verify: true
contexts:
- name: honeypath-canary
  context:
    cluster: honeypath-canary
    user: honeypath-canary
users:
- name: honeypath-canary
  user:
    token: eyJhbGciOiJIUzI1NiJ9.HONEYPATH_CANARY_NOT_A_REAL_TOKEN.000000
"""

_GCLOUD_ADC = (
    json.dumps(
        {
            "_honeypath": _HEADER,
            "client_id": "000000000000-honeypathcanary.apps.googleusercontent.invalid",
            "client_secret": "hpFAKEgcloudClientSecret000",
            "refresh_token": "1//0hHONEYPATHCANARYnotArealRefreshToken000000",
            "type": "authorized_user",
        },
        indent=2,
    )
    + "\n"
)

_AZURE_TOKENS = (
    json.dumps(
        [
            {
                "_honeypath": _HEADER,
                "tokenType": "Bearer",
                "expiresOn": "2000-01-01 00:00:00.000000",
                "userId": f"canary@{CANARY_HOST}",
                "accessToken": "eyJ0eXAiOiJKV1QifQ.HONEYPATH_CANARY_NOT_A_REAL_TOKEN.000",
                "refreshToken": "HONEYPATH_CANARY_NOT_A_REAL_REFRESH_TOKEN",
                "_clientId": "00000000-0000-0000-0000-000000000000",
            }
        ],
        indent=2,
    )
    + "\n"
)

_GH_HOSTS = f"""\
# {_HEADER}
git.{CANARY_HOST}:
    oauth_token: gho_HoneypathCanaryFAKEtoken0000000000000000
    user: honeypath-canary
    git_protocol: ssh
"""

_GIT_CREDENTIALS = (
    f"https://honeypath-canary:hpFAKEgitCredential000@git.{CANARY_HOST}\n"
)

_DBT_PROFILES = f"""\
# {_HEADER}
honeypath_canary:
  target: dev
  outputs:
    dev:
      type: postgres
      host: warehouse.{CANARY_HOST}
      port: 5432
      user: honeypath_canary
      password: hpFAKEdbtPassword000
      dbname: canary
      schema: public
      threads: 1
"""

_DOTENV = f"""\
# {_HEADER}
# This project directory exists only to bait credential scrapers.
DATABASE_URL=postgres://canary:hpFAKEdbPassword000@db.{CANARY_HOST}:5432/canary
REDIS_URL=redis://cache.{CANARY_HOST}:6379/0
STRIPE_SECRET_KEY=sk_live_HONEYPATHcanaryFAKEkey000000000000
GITHUB_TOKEN=ghp_HoneypathCanaryFAKEtoken000000000000
OPENAI_API_KEY=sk-HONEYPATHcanaryFAKEkey000000000000000000
SLACK_BOT_TOKEN=xoxb-000000000000-000000000000-HoneypathCanaryFAKE
JWT_SECRET=hpFAKEjwtSigningSecret000
"""

_GEM_CREDENTIALS = f"""\
# {_HEADER}
---
:honeypath_canary_api_key: hpFAKErubygemsKey000
"""

_COMPOSER_AUTH = (
    json.dumps(
        {
            "_honeypath": _HEADER,
            "http-basic": {
                f"repo.{CANARY_HOST}": {
                    "username": "honeypath-canary",
                    "password": "hpFAKEcomposerPassword000",
                }
            },
        },
        indent=2,
    )
    + "\n"
)

_MAVEN_SETTINGS = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!-- {_HEADER} -->
<settings>
  <servers>
    <server>
      <id>honeypath-canary</id>
      <username>honeypath-canary</username>
      <password>hpFAKEmavenPassword000</password>
    </server>
  </servers>
</settings>
"""

_GRADLE_PROPERTIES = f"""\
# {_HEADER}
honeypathCanaryRepoUrl=https://repo.{CANARY_HOST}/releases
honeypathCanaryRepoUser=honeypath-canary
honeypathCanaryRepoPassword=hpFAKEgradlePassword000
"""

_TERRAFORMRC = f"""\
# {_HEADER}
credentials "app.terraform.{CANARY_HOST}" {{
  token = "HoneypathCanaryFAKEterraformToken000.atlasv1.000"
}}
"""

# Only <packageSourceCredentials>; no <packageSources> entry is added, so
# NuGet never tries to contact the fake feed.
_NUGET_CONFIG = f"""\
<?xml version="1.0" encoding="utf-8"?>
<!-- {_HEADER} -->
<configuration>
  <packageSourceCredentials>
    <honeypath-canary>
      <add key="Username" value="honeypath-canary" />
      <add key="ClearTextPassword" value="hpFAKEnugetPassword000" />
    </honeypath-canary>
  </packageSourceCredentials>
</configuration>
"""

_YARNRC = f"""\
# {_HEADER}
npmRegistries:
  "https://registry.{CANARY_HOST}":
    npmAuthToken: "npm_HoneypathCanaryFAKEyarnToken0000000000"
"""

_HF_TOKEN = "hf_HoneypathCanaryFAKEtoken000000000000\n"

_DOCTL_CONFIG = f"""\
# {_HEADER}
access-token: dop_v1_honeypathcanaryFAKEtoken000000000000000000000000000000000000
context: default
"""

# --- crypto (opt-in only) -------------------------------------------------
# Nothing below is a valid key, seed, or wallet. The Electrum "seed" is not a
# valid BIP-39 mnemonic; the Solana file is a JSON *object*, not the 64-integer
# array a real keypair is serialised as.

_ELECTRUM_WALLET = (
    json.dumps(
        {
            "_honeypath": _HEADER,
            "seed_type": "segwit",
            "seed": "honeypath canary this is not a real seed phrase do not use",
            "wallet_type": "standard",
            "use_encryption": False,
        },
        indent=2,
    )
    + "\n"
)

# A real Solana keypair at ~/.config/solana/id.json is a 64-element array of
# byte values.  Emitting `[0]*64` reproduced that shape exactly — an all-zero
# but structurally valid keypair, which is closer to real key material than a
# canary should ever get.  A JSON object is unmistakably not a keypair: any
# tool that parses it fails immediately, and a human reading it sees why.
# Path-based stealers, which grab this file by name rather than by parsing it,
# are unaffected.
_SOLANA_KEYPAIR = (
    json.dumps(
        {
            "_honeypath": "HONEYPATH CANARY - NOT A SOLANA KEYPAIR",
            "warning": "This file contains no private key material.",
            "note": _HEADER,
        },
        indent=2,
    )
    + "\n"
)

_ETH_KEYSTORE = (
    json.dumps(
        {
            "_honeypath": _HEADER,
            "address": "0000000000000000000000000000000000000000",
            "crypto": {
                "cipher": "aes-128-ctr",
                "ciphertext": "00" * 32,
                "cipherparams": {"iv": "00" * 16},
                "kdf": "scrypt",
                "kdfparams": {
                    "dklen": 32,
                    "n": 262144,
                    "p": 1,
                    "r": 8,
                    "salt": "00" * 32,
                },
                "mac": "00" * 32,
            },
            "id": "00000000-0000-0000-0000-000000000000",
            "version": 3,
        },
        indent=2,
    )
    + "\n"
)

_WALLET_DAT = (
    f"{_HEADER}\n"
    "This is not a Berkeley DB wallet file and contains no keys.\n"
    "HONEYPATH CANARY - if something read this, a wallet stealer is active.\n"
)

_EXODUS_SEED = (
    f"{_HEADER}\n"
    "HONEYPATH CANARY - not an Exodus seed file, no key material inside.\n"
)

_MONERO_KEYS = f"{_HEADER}\n" "HONEYPATH CANARY - not a Monero wallet keys file.\n"


# --------------------------------------------------------------------------
# Entry construction
# --------------------------------------------------------------------------


_INTRUSIVENESS_FOR_CATEGORY = {
    CATEGORY_SAFE: INTRUSIVENESS_LOW,
    CATEGORY_ACTIVE: INTRUSIVENESS_ACTIVE,
    CATEGORY_WATCH: INTRUSIVENESS_HIGH,
    CATEGORY_SSH: INTRUSIVENESS_HIGH,
    CATEGORY_CRYPTO: INTRUSIVENESS_LOW,
}


def _dev_entries(platform: str, prefix: str) -> list[CanaryEntry]:
    """Developer-profile entries shared by Linux and macOS layouts.

    Category audit for this group:

    ``CATEGORY_SAFE`` — the file is a credential *store* whose entries are
    looked up by name (profile, host, registry, option group).  Adding one
    entry for a reserved ``.invalid`` target cannot change what an existing
    command resolves to:

      .aws/credentials      named [honeypath-canary] profile, no [default]
      .docker/config.json   auths keyed by registry hostname
      .npmrc                scoped @honeypath-canary registry, no bare registry=
      .pypirc               bare [honeypath-canary] section, no index-servers
      .cargo/credentials.toml   [registries.honeypath-canary]
      .pgpass               host-keyed, .invalid host only
      .my.cnf               [clienthoneypathcanary], never [client]

    ``CATEGORY_ACTIVE`` — the file occupies a path a tool consults on every
    invocation, or is itself the default credential:

      .config/gcloud/application_default_credentials.json
                            THE Application Default Credentials location;
                            google-auth picks it up with no configuration
      .azure/accessTokens.json
                            the Azure CLI token cache
      .kube/config          kubectl's default kubeconfig; present-but-contextless
                            is still a behaviour change
      .dbt/profiles.yml     dbt's sole configuration path; changes the failure
                            mode of every dbt run in every project
    """
    e = []

    def add(rel, key, kind, severity, category, content, mode=0o600, creatable=True):
        e.append(
            CanaryEntry(
                key=f"{prefix}.{key}",
                relative_path=rel,
                kind=kind,
                severity=severity,
                base_profile="developer",
                platform=platform,
                intrusiveness=_INTRUSIVENESS_FOR_CATEGORY[category],
                content=content,
                mode=mode,
                creatable=creatable,
                ssh_gated=_under_ssh(rel),
                category=category,
            )
        )

    add(
        ".ssh/id_rsa",
        "ssh.id_rsa",
        "ssh_private_key",
        "critical",
        CATEGORY_SSH,
        _SSH_PRIVATE_KEY,
    )
    add(
        ".ssh/id_ed25519",
        "ssh.id_ed25519",
        "ssh_private_key",
        "critical",
        CATEGORY_SSH,
        _SSH_PRIVATE_KEY,
    )
    add(
        ".ssh/config",
        "ssh.config",
        "ssh_config",
        "high",
        CATEGORY_SSH,
        _SSH_CANARY_CONFIG,
        mode=0o644,
    )
    add(
        ".ssh/known_hosts",
        "ssh.known_hosts",
        "ssh_known_hosts",
        "medium",
        CATEGORY_SSH,
        _SSH_KNOWN_HOSTS,
        mode=0o644,
    )
    add(
        ".aws/credentials",
        "aws.credentials",
        "aws_credentials",
        "critical",
        CATEGORY_SAFE,
        aws_credentials_content(),
    )
    add(
        ".config/gcloud/application_default_credentials.json",
        "gcloud.adc",
        "gcloud_credentials",
        "critical",
        CATEGORY_ACTIVE,
        _GCLOUD_ADC,
    )
    add(
        ".azure/accessTokens.json",
        "azure.tokens",
        "azure_credentials",
        "high",
        CATEGORY_ACTIVE,
        _AZURE_TOKENS,
    )
    add(
        ".kube/config",
        "kube.config",
        "kubeconfig",
        "high",
        CATEGORY_ACTIVE,
        _KUBE_CONFIG,
    )
    add(
        ".docker/config.json",
        "docker.config",
        "docker_credentials",
        "high",
        CATEGORY_SAFE,
        _DOCKER_CONFIG,
    )
    add(".npmrc", "npmrc", "npm_token", "high", CATEGORY_SAFE, _NPMRC)
    add(".pypirc", "pypirc", "pypi_token", "high", CATEGORY_SAFE, _PYPIRC)
    add(
        ".cargo/credentials.toml",
        "cargo.credentials",
        "cargo_token",
        "high",
        CATEGORY_SAFE,
        _CARGO_CREDENTIALS,
    )
    # .netrc is deliberately absent. git's HTTP transport turns on libcurl's
    # CURLOPT_NETRC, so every push or fetch over HTTPS reads ~/.netrc before the
    # credential helper runs — the canary fires on ordinary work, not on an
    # intruder, and a canary that cries wolf on `git push` trains you to ignore it.
    add(".pgpass", "pgpass", "pgpass", "high", CATEGORY_SAFE, _PGPASS)
    add(".my.cnf", "my.cnf", "mysql_credentials", "high", CATEGORY_SAFE, _MY_CNF)
    add(
        ".dbt/profiles.yml",
        "dbt.profiles",
        "dbt_credentials",
        "medium",
        CATEGORY_ACTIVE,
        _DBT_PROFILES,
    )
    return e


def _supply_chain_entries(
    platform: str, prefix: str, gh_hosts_rel: str
) -> list[CanaryEntry]:
    """Supply-chain entries.  Category audit:

    ``CATEGORY_ACTIVE``:

      gh hosts.yml          gh infers the default host from hosts.yml when it
                            holds a single entry, so this can repoint gh
      .huggingface/token    THE huggingface_hub token file; its presence makes
                            the client believe it is logged in
      .config/doctl/config.yaml
                            doctl's sole config, and `access-token` is the
                            default credential it authenticates with

    ``CATEGORY_SAFE`` — additive, name-keyed, no default changed:

      .gem/credentials      :honeypath_canary_api_key:, never :rubygems_api_key:
      .composer/auth.json   http-basic keyed by host
      .m2/settings.xml      a <server> id no repository references
      .gradle/gradle.properties
                            custom honeypathCanary* keys only; no org.gradle.*
                            key, so no Gradle behaviour is configured
      .terraformrc          a `credentials` block keyed by hostname; Terraform's
                            defaults for everything else still apply
      .yarnrc.yml           npmRegistries keyed by URL; npmRegistryServer unset
    """
    e = []

    def add(rel, key, kind, severity, category, content, mode=0o600):
        e.append(
            CanaryEntry(
                key=f"{prefix}.{key}",
                relative_path=rel,
                kind=kind,
                severity=severity,
                base_profile="supply-chain",
                platform=platform,
                intrusiveness=_INTRUSIVENESS_FOR_CATEGORY[category],
                content=content,
                mode=mode,
                category=category,
            )
        )

    add(
        gh_hosts_rel, "gh.hosts", "github_token", "critical", CATEGORY_ACTIVE, _GH_HOSTS
    )
    add(
        ".gem/credentials",
        "gem.credentials",
        "rubygems_token",
        "high",
        CATEGORY_SAFE,
        _GEM_CREDENTIALS,
    )
    add(
        ".composer/auth.json",
        "composer.auth",
        "composer_token",
        "medium",
        CATEGORY_SAFE,
        _COMPOSER_AUTH,
    )
    add(
        ".m2/settings.xml",
        "maven.settings",
        "maven_credentials",
        "medium",
        CATEGORY_SAFE,
        _MAVEN_SETTINGS,
    )
    add(
        ".gradle/gradle.properties",
        "gradle.properties",
        "gradle_credentials",
        "medium",
        CATEGORY_SAFE,
        _GRADLE_PROPERTIES,
    )
    add(
        ".terraformrc",
        "terraformrc",
        "terraform_token",
        "high",
        CATEGORY_SAFE,
        _TERRAFORMRC,
    )
    add(".yarnrc.yml", "yarnrc", "yarn_token", "medium", CATEGORY_SAFE, _YARNRC)
    add(
        ".huggingface/token",
        "huggingface.token",
        "huggingface_token",
        "medium",
        CATEGORY_ACTIVE,
        _HF_TOKEN,
    )
    add(
        ".config/doctl/config.yaml",
        "doctl.config",
        "digitalocean_token",
        "high",
        CATEGORY_ACTIVE,
        _DOCTL_CONFIG,
    )
    return e


def _crypto_entries(platform: str, prefix: str, specs) -> list[CanaryEntry]:
    return [
        CanaryEntry(
            key=f"{prefix}.{key}",
            relative_path=rel,
            kind=kind,
            severity="critical",
            base_profile="crypto",
            platform=platform,
            intrusiveness=_INTRUSIVENESS_FOR_CATEGORY[CATEGORY_CRYPTO],
            content=content,
            category=CATEGORY_CRYPTO,
        )
        for rel, key, kind, content in specs
    ]


def _noisy_entries(platform: str, prefix: str, specs) -> list[CanaryEntry]:
    return [
        CanaryEntry(
            key=f"{prefix}.{key}",
            relative_path=rel,
            kind=kind,
            severity="high",
            base_profile="browser-noisy",
            platform=platform,
            intrusiveness=_INTRUSIVENESS_FOR_CATEGORY[CATEGORY_WATCH],
            content="",
            creatable=False,
            category=CATEGORY_WATCH,
        )
        for rel, key, kind in specs
    ]


def _build_linux() -> list[CanaryEntry]:
    entries = _dev_entries(PLATFORM_LINUX, "linux")
    entries.append(
        CanaryEntry(
            key="linux.project.env",
            relative_path="honeypath-canary-project/.env",
            kind="dotenv",
            severity="high",
            base_profile="developer",
            platform=PLATFORM_LINUX,
            intrusiveness=INTRUSIVENESS_LOW,
            content=_DOTENV,
            # A directory that exists only as bait; no tool reads it.
            category=CATEGORY_SAFE,
        )
    )
    entries += _supply_chain_entries(PLATFORM_LINUX, "linux", ".config/gh/hosts.yml")
    entries += _crypto_entries(
        PLATFORM_LINUX,
        "linux",
        [
            (
                ".electrum/wallets/default_wallet",
                "electrum.wallet",
                "crypto_wallet",
                _ELECTRUM_WALLET,
            ),
            (
                ".config/solana/id.json",
                "solana.keypair",
                "crypto_keypair",
                _SOLANA_KEYPAIR,
            ),
            (
                ".ethereum/keystore/UTC--2019-01-01T00-00-00.000000000Z--0000000000000000000000000000000000000000",
                "ethereum.keystore",
                "crypto_keystore",
                _ETH_KEYSTORE,
            ),
            (".bitcoin/wallet.dat", "bitcoin.wallet", "crypto_wallet", _WALLET_DAT),
            (
                ".config/Exodus/exodus.wallet/seed.seco",
                "exodus.seed",
                "crypto_wallet",
                _EXODUS_SEED,
            ),
            (".monero/wallet.keys", "monero.keys", "crypto_wallet", _MONERO_KEYS),
        ],
    )
    entries += _noisy_entries(
        PLATFORM_LINUX,
        "linux",
        [
            (".mozilla/firefox/*/logins.json", "firefox.logins", "browser_logins"),
            (
                ".config/google-chrome/Default/Login Data",
                "chrome.logins",
                "browser_logins",
            ),
            (
                ".config/chromium/Default/Login Data",
                "chromium.logins",
                "browser_logins",
            ),
            (
                ".config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
                "chrome.metamask",
                "browser_wallet_extension",
            ),
        ],
    )
    return entries


def _build_windows() -> list[CanaryEntry]:
    """WSL-visible Windows-home entries (paths relative to the Windows home)."""

    def dev(rel, key, kind, severity, category, content, mode=0o600):
        return CanaryEntry(
            key=f"windows.{key}",
            relative_path=rel,
            kind=kind,
            severity=severity,
            base_profile="developer",
            platform=PLATFORM_WINDOWS,
            intrusiveness=_INTRUSIVENESS_FOR_CATEGORY[category],
            content=content,
            mode=mode,
            ssh_gated=_under_ssh(rel),
            category=category,
        )

    # Categories mirror the Linux audit above; the Windows home is a different
    # location for the same tools.
    entries = [
        dev(
            ".ssh/id_rsa",
            "ssh.id_rsa",
            "ssh_private_key",
            "critical",
            CATEGORY_SSH,
            _SSH_PRIVATE_KEY,
        ),
        dev(
            ".ssh/id_ed25519",
            "ssh.id_ed25519",
            "ssh_private_key",
            "critical",
            CATEGORY_SSH,
            _SSH_PRIVATE_KEY,
        ),
        dev(
            ".ssh/config",
            "ssh.config",
            "ssh_config",
            "high",
            CATEGORY_SSH,
            _SSH_CANARY_CONFIG,
            mode=0o644,
        ),
        dev(
            ".aws/credentials",
            "aws.credentials",
            "aws_credentials",
            "critical",
            CATEGORY_SAFE,
            aws_credentials_content(),
        ),
        # git's credential store is keyed by URL; an entry for a .invalid host
        # is never matched against a real remote.
        dev(
            ".git-credentials",
            "git.credentials",
            "git_credentials",
            "critical",
            CATEGORY_SAFE,
            _GIT_CREDENTIALS,
        ),
        dev(".npmrc", "npmrc", "npm_token", "high", CATEGORY_SAFE, _NPMRC),
        dev(".pypirc", "pypirc", "pypi_token", "high", CATEGORY_SAFE, _PYPIRC),
        dev(
            ".cargo/credentials.toml",
            "cargo.credentials",
            "cargo_token",
            "high",
            CATEGORY_SAFE,
            _CARGO_CREDENTIALS,
        ),
        dev(
            ".kube/config",
            "kube.config",
            "kubeconfig",
            "high",
            CATEGORY_ACTIVE,
            _KUBE_CONFIG,
        ),
        dev(
            ".docker/config.json",
            "docker.config",
            "docker_credentials",
            "high",
            CATEGORY_SAFE,
            _DOCKER_CONFIG,
        ),
        dev(
            ".dbt/profiles.yml",
            "dbt.profiles",
            "dbt_credentials",
            "medium",
            CATEGORY_ACTIVE,
            _DBT_PROFILES,
        ),
        dev(
            "AppData/Roaming/GitHub CLI/hosts.yml",
            "gh.hosts",
            "github_token",
            "critical",
            CATEGORY_ACTIVE,
            _GH_HOSTS,
        ),
    ]

    def sc(rel, key, kind, severity, category, content):
        return CanaryEntry(
            key=f"windows.{key}",
            relative_path=rel,
            kind=kind,
            severity=severity,
            base_profile="supply-chain",
            platform=PLATFORM_WINDOWS,
            intrusiveness=_INTRUSIVENESS_FOR_CATEGORY[category],
            content=content,
            category=category,
        )

    entries += [
        sc(
            ".gem/credentials",
            "gem.credentials",
            "rubygems_token",
            "high",
            CATEGORY_SAFE,
            _GEM_CREDENTIALS,
        ),
        sc(
            ".composer/auth.json",
            "composer.auth",
            "composer_token",
            "medium",
            CATEGORY_SAFE,
            _COMPOSER_AUTH,
        ),
        sc(
            ".m2/settings.xml",
            "maven.settings",
            "maven_credentials",
            "medium",
            CATEGORY_SAFE,
            _MAVEN_SETTINGS,
        ),
        # <packageSourceCredentials> only; no <packageSources> entry is added,
        # so NuGet never learns about the fake feed and never contacts it.
        sc(
            "AppData/Roaming/NuGet/NuGet.Config",
            "nuget.config",
            "nuget_credentials",
            "medium",
            CATEGORY_SAFE,
            _NUGET_CONFIG,
        ),
        sc(
            ".terraformrc",
            "terraformrc",
            "terraform_token",
            "high",
            CATEGORY_SAFE,
            _TERRAFORMRC,
        ),
        sc(".yarnrc.yml", "yarnrc", "yarn_token", "medium", CATEGORY_SAFE, _YARNRC),
    ]

    entries += _crypto_entries(
        PLATFORM_WINDOWS,
        "windows",
        [
            (
                "AppData/Roaming/Electrum/wallets/default_wallet",
                "electrum.wallet",
                "crypto_wallet",
                _ELECTRUM_WALLET,
            ),
            (
                "AppData/Roaming/Exodus/exodus.wallet/seed.seco",
                "exodus.seed",
                "crypto_wallet",
                _EXODUS_SEED,
            ),
            (
                "AppData/Roaming/Bitcoin/wallet.dat",
                "bitcoin.wallet",
                "crypto_wallet",
                _WALLET_DAT,
            ),
            (
                "AppData/Roaming/Ethereum/keystore/UTC--2019-01-01T00-00-00.000000000Z--0000000000000000000000000000000000000000",
                "ethereum.keystore",
                "crypto_keystore",
                _ETH_KEYSTORE,
            ),
        ],
    )
    entries += _noisy_entries(
        PLATFORM_WINDOWS,
        "windows",
        [
            (
                "AppData/Local/Google/Chrome/User Data/Default/Login Data",
                "chrome.logins",
                "browser_logins",
            ),
            (
                "AppData/Roaming/Mozilla/Firefox/Profiles/*/logins.json",
                "firefox.logins",
                "browser_logins",
            ),
            (
                "AppData/Local/Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
                "chrome.metamask",
                "browser_wallet_extension",
            ),
        ],
    )
    return entries


def _build_macos() -> list[CanaryEntry]:
    # The Linux developer list minus the canary project directory.
    entries = _dev_entries(PLATFORM_MACOS, "macos")
    entries += _supply_chain_entries(
        PLATFORM_MACOS, "macos", "Library/Application Support/GitHub CLI/hosts.yml"
    )
    entries += _crypto_entries(
        PLATFORM_MACOS,
        "macos",
        [
            (
                ".electrum/wallets/default_wallet",
                "electrum.wallet",
                "crypto_wallet",
                _ELECTRUM_WALLET,
            ),
            (
                ".config/solana/id.json",
                "solana.keypair",
                "crypto_keypair",
                _SOLANA_KEYPAIR,
            ),
            (
                "Library/Application Support/Exodus/exodus.wallet/seed.seco",
                "exodus.seed",
                "crypto_wallet",
                _EXODUS_SEED,
            ),
            (".bitcoin/wallet.dat", "bitcoin.wallet", "crypto_wallet", _WALLET_DAT),
        ],
    )
    entries += _noisy_entries(
        PLATFORM_MACOS,
        "macos",
        [
            (
                "Library/Application Support/Google/Chrome/Default/Login Data",
                "chrome.logins",
                "browser_logins",
            ),
            (
                "Library/Application Support/Firefox/Profiles/*/logins.json",
                "firefox.logins",
                "browser_logins",
            ),
        ],
    )
    return entries


CATALOG: list[CanaryEntry] = _build_linux() + _build_windows() + _build_macos()

ALL_PROFILES: list[str] = sorted({e.profile for e in CATALOG})


def entries_for_profiles(
    profiles, *, include_active_config: bool = True
) -> list[CanaryEntry]:
    """Entries belonging to ``profiles``.

    With ``include_active_config=False`` (the default for ``plan`` and
    ``create-canaries``), behaviour-changing active configuration is filtered
    out entirely — it is never planned, never created, never recorded.
    """
    wanted = set(profiles)
    return [
        e
        for e in CATALOG
        if e.profile in wanted
        and (include_active_config or e.category != CATEGORY_ACTIVE)
    ]


def active_config_entries(profiles) -> list[CanaryEntry]:
    """The active-config entries a set of profiles would contribute."""
    wanted = set(profiles)
    return [e for e in CATALOG if e.profile in wanted and e.category == CATEGORY_ACTIVE]


def ssh_entries(platform: str = PLATFORM_LINUX) -> list[CanaryEntry]:
    """Canaries planted into ~/.ssh by `setup-ssh-canary --activate`."""
    return [e for e in CATALOG if e.platform == platform and e.ssh_gated]


def expand_profile_names(
    names,
    *,
    os_name: str,
    has_windows_home: bool,
    include_crypto: bool = False,
    include_noisy: bool = False,
    default_profiles=None,
) -> tuple[list[str], list[str]]:
    """Resolve user-supplied profile names to concrete platform profiles.

    Returns ``(profiles, warnings)``.
    """
    from .platform_detect import OS_MACOS, OS_WSL

    warnings: list[str] = []
    native_prefix = "macos" if os_name == OS_MACOS else "linux"

    # (profile name, was it named explicitly rather than pulled in by "auto")
    resolved: list[tuple[str, bool]] = []
    for raw in names:
        name = raw.strip()
        if not name:
            continue
        if name == "auto":
            resolved.extend((p, False) for p in (default_profiles or []))
            continue
        if name in ALL_PROFILES:
            resolved.append((name, True))
            continue
        if name in BASE_PROFILES:
            resolved.append((f"{native_prefix}-{name}", True))
            if os_name == OS_WSL and has_windows_home:
                resolved.append((f"wsl-windows-{name}", True))
            continue
        warnings.append(f"unknown profile ignored: {name}")

    # Crypto and browser-noisy are opt-in: allowed either by their flag or by
    # being named explicitly on the command line.
    final: list[str] = []
    excluded: set[str] = set()
    for name, explicit in resolved:
        if name.endswith("-crypto") and not (include_crypto or explicit):
            if name not in excluded:
                excluded.add(name)
                warnings.append(f"{name} excluded (pass --include-crypto to enable)")
            continue
        if name.endswith("-browser-noisy") and not (include_noisy or explicit):
            if name not in excluded:
                excluded.add(name)
                warnings.append(f"{name} excluded (pass --include-noisy to enable)")
            continue
        if name not in final:
            final.append(name)
    return final, warnings


# --------------------------------------------------------------------------
# Creating canary files on disk
# --------------------------------------------------------------------------


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def managed_marker(canary_id: str) -> str:
    """Stable, per-canary identity stored beside the exact content hash."""
    return (
        "honeypath-managed-"
        + hashlib.sha256(
            ("honeypath-canary-id\0" + canary_id).encode("utf-8")
        ).hexdigest()
    )


def _ancestor_chain(directory: Path, root: Path | str) -> list[Path]:
    """``directory`` and every ancestor below ``root``, outermost first.

    Falls back to just ``directory`` when it is not under ``root``; safe_mkdir
    performs the real containment check and refuses anything outside.
    """
    try:
        parts = directory.relative_to(Path(root)).parts
    except ValueError:
        return [directory]
    base = Path(root)
    return [base.joinpath(*parts[: i + 1]) for i in range(len(parts))]


def render_content(entry: CanaryEntry, *, canarytoken: dict | None = None) -> str:
    """Materialise an entry's content, applying any Canarytoken splice."""
    if canarytoken and entry.kind == "aws_credentials":
        return aws_credentials_content(canarytoken)
    return entry.content


class CanaryCreateResult:
    __slots__ = ("path", "created", "reason", "problems")

    def __init__(self, path: Path, created: bool, reason: str, problems=None):
        self.path = path
        self.created = created
        self.reason = reason
        self.problems = problems or []


# Every canary Honeypath writes is self-identifying.  ``--refresh-managed``
# refuses to replace any file that does not carry this marker, which is what
# stops a real credential file from ever being treated as refreshable.
CONTENT_MARKER = "honeypath"


def content_has_marker(text: str) -> bool:
    """True when ``text`` is recognisably Honeypath-authored content."""
    return CONTENT_MARKER in text.lower()


def file_has_marker(path: Path) -> bool:
    """True when the file on disk carries the Honeypath content marker.

    Read with ``O_NOFOLLOW`` so a symlink cannot make an unrelated file look
    Honeypath-managed.
    """
    try:
        return content_has_marker(safe_write.read_text_nofollow(path))
    except (OSError, safe_write.SafeWriteError):
        return False


def create_canary_file(
    path: Path,
    content: str,
    mode: int,
    target: TargetUserContext,
    *,
    replace_managed: bool = False,
    dry_run: bool = False,
    best_effort: bool = False,
    root: Path | str | None = None,
    expected_content_hash: str | None = None,
    durable: bool = False,
    on_installed: Callable[[], None] | None = None,
) -> CanaryCreateResult:
    """Write one canary.  An existing path is *never* clobbered by default.

    ``replace_managed`` is the only way to replace an existing file, and the
    caller must already have verified that the path is Honeypath-managed (see
    :func:`cli.refresh_is_permitted`).  Even then, only a regular file is
    replaced: symlinks, directories, sockets, FIFOs and device nodes are
    always refused.

    ``root`` is the containment root for the symlink-safety checks; it
    defaults to the target user's home.  Windows homes under /mnt pass their
    own root.

    ``on_installed`` is the caller's chance to reject a write that has already
    landed — registering it in the manifest, say.  It runs while the previous
    file is still recoverable, so raising from it puts that file back and
    leaves nothing new on disk.  See :func:`safe_write.atomic_write`.
    """
    root = Path(root) if root is not None else target.home

    # lstat, not exists(): a dangling symlink must still be refused.
    try:
        info = safe_write.stat_nofollow(path, root=root)
    except FileNotFoundError:
        info = None
    except OSError as exc:
        return CanaryCreateResult(path, False, f"refused: cannot inspect path: {exc}")

    if info is not None:
        if stat.S_ISLNK(info.st_mode):
            return CanaryCreateResult(path, False, "refused: path is a symlink")
        if not stat.S_ISREG(info.st_mode):
            return CanaryCreateResult(
                path, False, "refused: path exists and is not a regular file"
            )
        if not replace_managed:
            return CanaryCreateResult(path, False, "skipped: file already exists")

    if dry_run:
        return CanaryCreateResult(path, False, "would create")

    problems: list[str] = []
    try:
        # Each ancestor is created with a mode chosen from its *own* name, not
        # from the immediate parent's: ~/.config/gcloud must leave ~/.config
        # at 0700 even though "gcloud" itself is not dot-prefixed.  safe_mkdir
        # only applies metadata to directories it actually creates, so walking
        # the chain prefix by prefix is idempotent.
        for ancestor in _ancestor_chain(path.parent, root):
            problems += safe_write.safe_mkdir(
                ancestor,
                root,
                mode=0o700 if ancestor.name.startswith(".") else 0o755,
                uid=target.uid,
                gid=target.gid,
            )
    except safe_write.SafeWriteError as exc:
        return CanaryCreateResult(path, False, f"refused: {exc}")
    except OSError as exc:
        return CanaryCreateResult(
            path, False, f"failed: cannot create {path.parent}: {exc}"
        )

    try:
        problems += safe_write.atomic_write(
            path,
            content,
            mode=mode,
            root=root,
            uid=target.uid,
            gid=target.gid,
            # Canary content is reproducible from the catalog; a crash losing
            # it costs nothing.  Migrated credentials do get fsync'd.
            fsync_data=durable,
            replace=replace_managed,
            expected_sha256=expected_content_hash if replace_managed else None,
            # DrvFS/9p does not implement O_TMPFILE, and neither does any
            # non-Linux kernel: on macOS *every* write would otherwise be
            # refused and no canary could be created at all.  For brand-new
            # files use anchored O_EXCL creation instead: it may expose bytes
            # while they are written, but can never replace an existing
            # credential.  Replacement still requires the Linux CAS primitives.
            allow_exclusive_create_fallback=(
                (best_effort or not safe_write.supports_unnamed_temporary())
                and not replace_managed
            ),
            on_installed=on_installed,
        )
    except safe_write.RollbackError:
        # The write landed, was rejected, and could not be undone.  That is the
        # caller's emergency, not a path this function may report as "refused".
        raise
    except safe_write.SafeWriteError as exc:
        return CanaryCreateResult(path, False, f"refused: {exc}")
    except OSError as exc:
        return CanaryCreateResult(path, False, f"failed: {exc}")

    verb = "replaced" if info is not None else "created"
    if problems and not best_effort:
        # On a native filesystem these should not happen; surface them.
        return CanaryCreateResult(path, True, f"{verb} (with warnings)", problems)
    return CanaryCreateResult(path, True, verb, problems)


def expand_entry_paths(entry: CanaryEntry, home: Path) -> list[Path]:
    """Resolve an entry to concrete paths (glob entries may match several)."""
    if not entry.is_glob:
        return [entry.path_for(home)]
    try:
        return sorted(home.glob(entry.relative_path))
    except OSError:
        return []

import hashlib
import json
import re

ISSUER_VERSION = "credit-issuer production 0.6.0"
EPOCH = 4

REQUIRED_NAME = "David Solis"
REQUIRED_EMAIL = "doze.inept.0n@icloud.com"
REQUIRED_IDENT = (REQUIRED_NAME, REQUIRED_EMAIL)

REQUIRED_SECTIONS = ("Why:", "How:", "Tags:")

# Formatting compatibility only; every object still gets credit/identity checks.
TARGET_REPOSITORY = "soliskit/litmus-clean-v2"
TARGET_REPOSITORY_ID = 1466906910
HISTORICAL_FORMAT_OBJECTS = frozenset(
    (
        "1c96e348f003e53ea4e9f67c026aa32259fd54ff",
        "2ad9b91b895e9a0510455d3d519a2bb8e8d7ec62",
        "6200c2390ceea6322ac6ded567ae0cea4a0248b3",
        "7dfaccc4cbf6ea6b991a5b06501158742deae075",
        "a653b202d0f6daf2428a643e3b8f2c18273366c3",
        "cc609f20ddd089ecc3aefb12d30039dd92730299",
        "d0648f32fbf80c870a2c00149c24a824f96445f9",
        "d8eda55b82a97be26b14f5080ac3361e071d4d5e",
    )
)


PROHIBITED_ALTERNATIVES = [
    ("co-authored-trailer", r"^co-authored-by\s*:", r"^co-authored-by[[:space:]]*:"),
    ("generated-with-trailer", r"^generated-with\s*:", r"^generated-with[[:space:]]*:"),
    ("assisted-by-trailer", r"^assisted-by\s*:", r"^assisted-by[[:space:]]*:"),
    ("generated-phrase", r"generated (with|by)\b", r"generated (with|by)\b"),
    ("bracket-generated", r"\[generated", r"\[generated"),
    (
        "by-agent-name",
        r"\bby (claude|cursor|copilot|chatgpt|openai|anthropic|github copilot)\b",
        r"\bby (claude|cursor|copilot|chatgpt|openai|anthropic|github copilot)\b",
    ),
    (
        "agent-authored",
        r"\b(claude|cursor|copilot|chatgpt)[ -]?(co-?authored|generated)\b",
        r"\b(claude|cursor|copilot|chatgpt)[ -]?(co-?authored|generated)\b",
    ),
    (
        "vendor-noreply",
        r"noreply@(anthropic|openai)\.",
        r"noreply@(anthropic|openai)\.",
    ),
    ("robot-emoji", "\U0001f916", "\U0001f916"),
]

PROHIBITED_CREDIT = re.compile(
    "|".join(f"({p})" for _i, p, _s in PROHIBITED_ALTERNATIVES),
    re.IGNORECASE | re.MULTILINE | re.ASCII,
)


MAX_PARENTS = None
MAX_COMMITS = 10000


HEADER_ORDER = ("tree", "parent", "author", "committer")
OID_RE = re.compile(r"^[0-9a-f]{40}$")
IDENT_LINE_RE = re.compile(r"^(.*?) <([^<>]+)> (\d+) ([+-]\d{4})$")


def context_name(epoch=EPOCH):
    pass
    return f"Credit ancestry v2-e{epoch}"


def policy_config(epoch=EPOCH):
    return {
        "issuer_version": ISSUER_VERSION,
        "epoch": epoch,
        "required_author": list(REQUIRED_IDENT),
        "required_committer": list(REQUIRED_IDENT),
        "required_sections": list(REQUIRED_SECTIONS),
        "historical_format_objects": sorted(HISTORICAL_FORMAT_OBJECTS),
        "target_repository": TARGET_REPOSITORY,
        "target_repository_id": TARGET_REPOSITORY_ID,
        "format_scope": "new-object-only-with-exact-reviewed-format-compatibility",
        "prohibited_ids": [i for i, _p, _s in PROHIBITED_ALTERNATIVES],
        "max_parents": MAX_PARENTS,
        "max_commits": MAX_COMMITS,
        "header_order": list(HEADER_ORDER),
        "base_rule": "full-closure-walk-no-baseline-exemption",
    }


def policy_digest(epoch=EPOCH):
    return hashlib.sha256(
        json.dumps(policy_config(epoch), sort_keys=True).encode()
    ).hexdigest()


def code_digest():
    pass

    import pathlib

    return hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()


def check_message(message, sha=None):
    from project_bootstrap import publication_gate as project_profile

    if any(c in message for c in "\r\v\f\x1c\x1d\x1e\x85\u2028\u2029"):
        raise ValueError("ambiguous message line separator")
    project_profile.full_message(message.encode("utf-8"))
    m = PROHIBITED_CREDIT.search(message)
    if m:
        raise ValueError(f"prohibited credit/attribution: {m.group(0)!r}")
    if sha in HISTORICAL_FORMAT_OBJECTS:
        return
    for tag in REQUIRED_SECTIONS:
        lines = message.splitlines()
        positions = [i for i, line in enumerate(lines) if line.startswith(tag)]
        if len(positions) != 1:
            raise ValueError(f"message missing or repeated {tag}")
        start = positions[0]
        next_sections = [
            i
            for i in range(start + 1, len(lines))
            if any(lines[i].startswith(t) for t in REQUIRED_SECTIONS)
        ]
        end = min(next_sections, default=len(lines))
        value = "\n".join([lines[start][len(tag) :], *lines[start + 1 : end]])
        if not value.strip():
            raise ValueError(f"message empty {tag}")


def source_digests():
    pass
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    paths = sorted(root.glob("*.py"))
    for directory in ("baseline", "production_policy", "project_bootstrap"):
        paths.extend(sorted((root / directory).glob("*.py")))
        if (root / directory / "pre-push").is_file():
            paths.append(root / directory / "pre-push")
        paths.extend(sorted((root / directory).glob("*.json")))
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }


def source_digest():
    pass
    return hashlib.sha256(
        json.dumps(source_digests(), sort_keys=True).encode()
    ).hexdigest()

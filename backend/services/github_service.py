"""Scan public GitHub repositories via the official GitHub API.

Safety:
- Only api.github.com / raw.githubusercontent.com are contacted (fixed hosts,
  so there is no SSRF surface: the user controls only the owner/repo path
  segments, which are strictly validated)
- File count, per-file size, and total size are capped
- Only code file extensions are fetched
"""
import re
import httpx
from services.glm_service import analyze_code

GITHUB_API = "https://api.github.com"
RAW_BASE = "https://raw.githubusercontent.com"
USER_AGENT = "CodeGuardAI/2.0 (Educational security analysis)"

ALLOWED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".php",
    ".cpp", ".cc", ".cxx", ".h", ".hpp", ".cs", ".rs", ".rb", ".kt", ".swift",
}
SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "vendor", "venv", ".venv",
    "__pycache__", "target", "coverage", ".github",
}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock"}

MAX_FILES = 8
MAX_FILE_BYTES = 100_000
MAX_TOTAL_BYTES = 60_000


class RepoNotFound(ValueError):
    pass


def parse_repo_url(url: str):
    url = (url or "").strip()
    if len(url) > 500:
        raise ValueError("URL is too long.")
    m = re.match(
        r"^https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)"
        r"(?:/(?:tree|blob)/([^/?#]+)(?:/([^?#]*)))?/?$",
        url,
        re.IGNORECASE,
    )
    if not m:
        raise ValueError(
            "Not a valid GitHub repository URL. "
            "Example: https://github.com/owner/repo"
        )
    owner, repo, ref, path = m.group(1), m.group(2), m.group(3), m.group(4)
    repo = re.sub(r"\.git$", "", repo, flags=re.IGNORECASE)
    return owner, repo, ref, path


async def collect_repo_files(url: str):
    owner, repo, ref, path = parse_repo_url(url)

    async with httpx.AsyncClient(
        timeout=20.0, follow_redirects=True, headers={"User-Agent": USER_AGENT}
    ) as client:
        meta = await client.get(f"{GITHUB_API}/repos/{owner}/{repo}")
        if meta.status_code == 404:
            raise RepoNotFound("Repository not found or not public.")
        meta.raise_for_status()
        default_branch = meta.json().get("default_branch", "main")
        branch = ref or default_branch

        # Single-file URL (github.com/owner/repo/blob/<ref>/<path>)
        if path and "/blob/" in url:
            file_path = path
            raw = await client.get(
                f"{RAW_BASE}/{owner}/{repo}/{branch}/{file_path}"
            )
            if raw.status_code != 200:
                raise RepoNotFound("File not found in the repository.")
            return [(file_path, raw.text[:MAX_FILE_BYTES])]

        tree_resp = await client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}",
            params={"recursive": "1"},
        )
        if tree_resp.status_code == 404:
            raise RepoNotFound("Branch not found.")
        tree_resp.raise_for_status()
        tree = tree_resp.json().get("tree", [])

        candidates = []
        for item in tree:
            if item.get("type") != "blob":
                continue
            file_path = item.get("path", "")
            name = file_path.rsplit("/", 1)[-1]
            if any(part in SKIP_DIRS for part in file_path.split("/")):
                continue
            if name in SKIP_FILES:
                continue
            ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
            if ext not in ALLOWED_EXTENSIONS:
                continue
            if item.get("size", 0) > MAX_FILE_BYTES:
                continue
            if path and not file_path.startswith(path):
                continue
            candidates.append(file_path)

        # Prefer smaller files first so more of the repo fits in the budget.
        files = []
        total = 0
        for file_path in candidates:
            if len(files) >= MAX_FILES or total >= MAX_TOTAL_BYTES:
                break
            raw = await client.get(f"{RAW_BASE}/{owner}/{repo}/{branch}/{file_path}")
            if raw.status_code != 200:
                continue
            text = raw.text
            if total + len(text) > MAX_TOTAL_BYTES:
                text = text[: MAX_TOTAL_BYTES - total]
            files.append((file_path, text))
            total += len(text)

        if not files:
            raise RepoNotFound(
                "No supported code files found in this repository."
            )
        return files


async def analyze_github_repo(url: str, options=None, custom_rules=None) -> str:
    files = await collect_repo_files(url)
    combined = "\n\n".join(
        f"=== FILE: {path} ===\n{content}" for path, content in files
    )
    langs = sorted({p.rsplit(".", 1)[-1].lower() for p, _ in files})
    language = f"Multiple ({', '.join(langs)}) - GitHub repository"
    return await analyze_code(language, combined, options, custom_rules)

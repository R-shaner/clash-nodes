"""
自动发现订阅源（多路并行）：
  1. GitHub 仓库搜索：关键词 + topic，最近几天有推送，多页
  2. 每个仓库：读文件树，挑出疑似订阅文件；读 README，挖出里面的 Telegram 频道和订阅链接
  3. 返回：文件 raw 链接 + Telegram 频道预览页(https://t.me/s/<name>) + README 里挖到的订阅链接

返回的链接是否真的含节点，由 main.py 抓取后解析决定；没解析出节点的会被直接忽略，
有产出的会被记进状态文件，下一轮优先抓。
"""
import html
import os
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

import requests

ROOT = Path(__file__).resolve().parent
API = "https://api.github.com"
UA = {"User-Agent": "clash-nodes"}
MAX_REPOS = int(os.environ.get("MAX_REPOS", 60))            # 每轮最多检查多少个仓库
FILES_PER_REPO = int(os.environ.get("FILES_PER_REPO", 5))    # 每个仓库最多取几个文件
DISCOVER_DAYS = int(os.environ.get("DISCOVER_DAYS", 3))      # 只看最近 N 天有推送的仓库
SEARCH_PAGES = int(os.environ.get("SEARCH_PAGES", 2))        # 每个查询翻几页
MAX_CHANNELS = int(os.environ.get("MAX_CHANNELS", 30))       # 每轮最多挖多少个 Telegram 频道
MAX_LINKS = int(os.environ.get("MAX_LINKS", 40))             # 每轮最多跟进多少条挖到的订阅链接
MAX_REPO_KB = int(os.environ.get("MAX_REPO_KB", 100_000))    # 跳过体积过大的仓库(多半是客户端/大项目)
BUDGET = int(os.environ.get("DISCOVER_BUDGET", 300))         # 发现阶段总耗时上限(秒)

DEFAULT_QUERIES = [
    "clash free nodes",
    "free v2ray subscription",
    "free proxy nodes aggregator",
    "vmess vless trojan free nodes",
    "clash 订阅 免费节点",
    "免费节点 每日更新",
    "topic:v2ray",
    "topic:clash",
    "topic:vless",
    "topic:hysteria2",
]

GOOD_EXT = {"", ".txt", ".yaml", ".yml", ".list", ".conf", ".sub", ".base64"}
NAME_KEYS = ("clash", "v2ray", "sub", "node", "proxy", "vmess", "vless", "trojan",
             "ss", "mix", "all", "base64", "free", "share", "list", "config", "hy2", "hysteria")
BAD_PATH = re.compile(
    r"(^|/)(\.github|docs?|tests?|node_modules|\.git)/|readme|license|changelog|"
    r"requirements|package(-lock)?\.|\.md$|\.gitignore|\.py$|\.js$", re.I)
README_RE = re.compile(r"^readme(\.\w+)?$", re.I)

# ---- 从文本里挖频道/链接 ----
CHANNEL_RE = re.compile(r"(?:https?://)?t\.me/(?:s/)?([A-Za-z][A-Za-z0-9_]{4,31})\b")
CHANNEL_SKIP = {"joinchat", "share", "proxy", "socks", "addstickers", "addtheme", "addemoji",
                "setlanguage", "login", "contact", "boost", "giftcode", "telegram", "durov", "iv"}
LINK_RE = re.compile(r"https?://[^\s)<>\"'\]\\]+")
GOOD_HOST = re.compile(r"(^|\.)(raw\.githubusercontent\.com|gist\.githubusercontent\.com|"
                       r"cdn\.jsdelivr\.net|fastly\.jsdelivr\.net|github\.io|pages\.dev|workers\.dev)$")
LINK_HINT = re.compile(r"\.(txt|ya?ml|list|sub)(\?|$)|/(sub|subscribe|clash|v2ray|nodes?|proxies|link)\b|"
                       r"clash|v2ray|subscribe", re.I)
BAD_LINK = re.compile(r"\.(png|jpe?g|gif|svg|ico|webp|css|js|mp4|zip|apk|exe|dmg|pdf)(\?|$)|"
                      r"shields\.io|badge|telegra\.ph/file|t\.me/", re.I)
BLOB_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$")


def log(*a):
    print(*a, flush=True)


def load_queries():
    f = ROOT / "queries.txt"
    if f.exists():
        qs = [l.strip() for l in f.read_text(encoding="utf-8").splitlines()
              if l.strip() and not l.strip().startswith("#")]
        if qs:
            return qs
    return DEFAULT_QUERIES


def safe_url(url):
    """只跟进公网 https 域名，挡掉 IP 字面量、localhost、内网域名。"""
    try:
        u = urlparse(url)
        host = (u.hostname or "").lower()
        if u.scheme != "https" or not host:
            return False
        if re.fullmatch(r"[\d.]+", host) or ":" in host:
            return False
        if host == "localhost" or host.endswith((".local", ".internal", ".lan", ".localhost")):
            return False
        return "." in host
    except Exception:
        return False


def mine_links(text):
    """从 README / 网页文本里挖：(Telegram 频道预览页集合, 疑似订阅链接集合)。"""
    text = html.unescape(text or "")
    channels, links = set(), set()
    for name in CHANNEL_RE.findall(text):
        if name.lower() in CHANNEL_SKIP or name.lower().endswith("bot"):
            continue
        channels.add(f"https://t.me/s/{name}")
    for url in LINK_RE.findall(text):
        url = url.rstrip(".,;:!*_`")
        m = BLOB_RE.match(url)
        if m:
            url = "https://raw.githubusercontent.com/{}/{}/{}/{}".format(*m.groups())
        if BAD_LINK.search(url) or not safe_url(url):
            continue
        host = urlparse(url).hostname.lower()
        if GOOD_HOST.search(host) or LINK_HINT.search(url):
            links.add(url)
    return channels, links


def gh(path, **params):
    """返回 json；被限流返回 None。"""
    headers = {"Accept": "application/vnd.github+json", **UA}
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    r = requests.get(API + path, params=params, headers=headers, timeout=20)
    if r.status_code in (403, 429):
        return None
    r.raise_for_status()
    return r.json()


def fetch_raw(url, limit=400_000):
    try:
        r = requests.get(url, timeout=15, stream=True, headers=UA)
        if r.status_code != 200:
            return ""
        return r.raw.read(limit, decode_content=True).decode("utf-8", "ignore")
    except Exception:
        return ""


def pick_files(tree):
    """从仓库文件树里挑最像订阅文件的几个。"""
    cands = []
    for t in tree:
        if t.get("type") != "blob":
            continue
        path, size = t["path"], t.get("size", 0)
        if BAD_PATH.search(path) or not (800 <= size <= 3_000_000):
            continue
        name = path.rsplit("/", 1)[-1].lower()
        ext = os.path.splitext(name)[1]
        if ext not in GOOD_EXT:
            continue
        score = sum(k in name for k in NAME_KEYS) * 2 + (1 if ext in (".yaml", ".yml", ".txt") else 0)
        if ext == "" and score == 0:
            continue
        cands.append((score, size, path))
    cands.sort(key=lambda x: (-x[0], -x[1]))
    return [p for _, _, p in cands[:FILES_PER_REPO]]


def repo_scan(repo):
    """返回 (订阅文件 raw 链接列表, README 文本)。"""
    name, branch = repo["full_name"], repo.get("default_branch") or "main"
    try:
        j = gh(f"/repos/{name}/git/trees/{branch}", recursive="1")
    except Exception:
        return [], ""
    if not j:
        return [], ""
    tree = j.get("tree", [])
    files = [f"https://raw.githubusercontent.com/{name}/{branch}/{quote(p)}" for p in pick_files(tree)]
    readme = next((t["path"] for t in tree
                   if t.get("type") == "blob" and "/" not in t["path"] and README_RE.match(t["path"])), None)
    text = fetch_raw(f"https://raw.githubusercontent.com/{name}/{branch}/{quote(readme)}") if readme else ""
    return files, text


def search_repos(deadline):
    since = (datetime.now(timezone.utc) - timedelta(days=DISCOVER_DAYS)).strftime("%Y-%m-%d")
    repos = {}
    for q in load_queries():
        for page in range(1, SEARCH_PAGES + 1):
            if time.time() > deadline:
                log("  [发现] 达到时间预算，停止搜索")
                return repos
            try:
                j = gh("/search/repositories", q=f"{q} pushed:>={since}",
                       sort="updated", order="desc", per_page=30, page=page)
            except Exception as e:
                log(f"  [发现] 搜索失败 {q!r} ({type(e).__name__})")
                break
            if j is None:
                log("  [发现] GitHub API 被限流，提前结束搜索")
                return repos
            items = j.get("items", [])
            for it in items:
                if it.get("fork") or it.get("archived") or not it.get("size"):
                    continue
                if it["size"] > MAX_REPO_KB:
                    continue
                repos[it["full_name"]] = it
            time.sleep(2)  # 搜索接口 30 次/分钟
            if len(items) < 30:
                break
    return repos


def discover():
    deadline = time.time() + BUDGET
    repos = search_repos(deadline)
    ranked = sorted(repos.values(), key=lambda r: -r.get("stargazers_count", 0))[:MAX_REPOS]

    files, channels, links = [], set(), set()
    with ThreadPoolExecutor(6) as ex:
        for fs, text in ex.map(repo_scan, ranked):
            files += fs
            ch, ln = mine_links(text)
            channels |= ch
            links |= ln
    # 随机取样：每小时换一批，状态文件会记住有产出的
    channels = random.sample(sorted(channels), min(len(channels), MAX_CHANNELS))
    links = random.sample(sorted(links), min(len(links), MAX_LINKS))
    log(f"  [发现] 候选仓库 {len(repos)} 个，检查 {len(ranked)} 个 → "
        f"文件 {len(files)}、Telegram 频道 {len(channels)}、README 链接 {len(links)}")
    return list(dict.fromkeys(files + channels + links))

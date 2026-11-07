#!/usr/bin/env python3
"""
每小时跑一次的节点流水线：
  抓取订阅源 -> 解析 -> 去重 -> TCP 预筛 -> mihomo 延迟测试 -> 真实下载测速(顺便识别出口国家)
  -> 生成 clash.yaml / proxies.yaml / status.json
"""
import base64
import concurrent.futures as cf
import html
import json
import os
import random
import re
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import requests
import yaml

import discover

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "output"
MIHOMO = os.environ.get("MIHOMO_BIN", str(ROOT / "mihomo"))

# ---------- 可调参数（环境变量覆盖）----------
MAX_CANDIDATES = int(os.environ.get("MAX_CANDIDATES", 1500))  # 进入延迟测试的上限
MAX_DELAY_MS = int(os.environ.get("MAX_DELAY_MS", 1500))      # 延迟超过则丢弃
SPEED_TOP = int(os.environ.get("SPEED_TOP", 150))             # 延迟最低的前 N 个做测速
MIN_SPEED = float(os.environ.get("MIN_SPEED", 0.5))           # MB/s，低于则丢弃
KEEP = int(os.environ.get("KEEP", 100))                       # 最终保留节点数
PER_COUNTRY = int(os.environ.get("PER_COUNTRY", 15))          # 每个国家最多保留
SPEED_SECS = 6                                                # 单节点测速时长
DELAY_URL = "https://www.gstatic.com/generate_204"
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=20000000"
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
MAX_PREFILTER = int(os.environ.get("MAX_PREFILTER", 6000))   # 进入 TCP 预筛的上限
MAX_STATE = int(os.environ.get("MAX_STATE", 300))            # 历史来源池上限，按有效节点数保留
TG_PAGES = int(os.environ.get("TG_PAGES", 3))                # Telegram 频道每个翻几页(每页约 20 条消息)
DEAD_LIMIT = int(os.environ.get("DEAD_LIMIT", 6))            # 来源连续 N 轮没有有效节点就不再抓
STATE_FILE = ROOT / ".cache" / "sources.json"                # 由 Actions cache 跨轮保存
YLoader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
URI_RE = re.compile(r"(?:vmess|vless|trojan|ss|hysteria2|hy2)://[^\s\"'<>\\]+")
API_PORT = 19090
LISTEN_BASE = 20000

SUPPORTED = {"ss", "vmess", "vless", "trojan", "hysteria2"}
SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")
CN_NAME = {
    "HK": "香港", "TW": "台湾", "JP": "日本", "SG": "新加坡", "US": "美国",
    "KR": "韩国", "GB": "英国", "DE": "德国", "FR": "法国", "CA": "加拿大",
    "AU": "澳大利亚", "RU": "俄罗斯", "IN": "印度", "NL": "荷兰", "TR": "土耳其",
}


def log(*a):
    print(*a, flush=True)


# =====================================================================
# 1. 抓取 & 解析
# =====================================================================
def b64d(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def parse_ss(u):
    u = u[5:]
    name = ""
    if "#" in u:
        u, name = u.split("#", 1)
        name = unquote(name)
    if "?" in u:  # 带 plugin 的先不支持
        return None
    if "@" not in u:
        u = b64d(u).decode()
    userinfo, hostport = u.rsplit("@", 1)
    if ":" not in userinfo:
        userinfo = b64d(unquote(userinfo)).decode()
    method, pwd = userinfo.split(":", 1)
    host, port = hostport.rsplit(":", 1)
    return {"name": name or host, "type": "ss", "server": host.strip("[]"),
            "port": int(port), "cipher": method, "password": pwd, "udp": True}


def parse_vmess(u):
    j = json.loads(b64d(u[8:]).decode())
    p = {"name": j.get("ps") or j["add"], "type": "vmess", "server": j["add"],
         "port": int(j["port"]), "uuid": j["id"],
         "alterId": int(j.get("aid") or 0), "cipher": j.get("scy") or "auto", "udp": True}
    if j.get("tls") in ("tls", True):
        p["tls"] = True
        if j.get("sni") or j.get("host"):
            p["servername"] = j.get("sni") or j.get("host")
        p["skip-cert-verify"] = True
    net = j.get("net", "tcp")
    if net == "ws":
        p["network"] = "ws"
        p["ws-opts"] = {"path": j.get("path") or "/",
                        "headers": {"Host": j.get("host") or j["add"]}}
    elif net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": j.get("path") or ""}
    elif net != "tcp":
        return None
    return p


def parse_vless_trojan(u):
    pu = urlparse(u)
    q = {k: v[0] for k, v in parse_qs(pu.query).items()}
    scheme = pu.scheme
    p = {"name": unquote(pu.fragment) or pu.hostname, "type": scheme,
         "server": pu.hostname, "port": pu.port, "udp": True}
    sec = q.get("security", "")
    sni = q.get("sni") or q.get("peer") or ""
    if scheme == "vless":
        p["uuid"] = unquote(pu.username or "")
        if q.get("flow"):
            p["flow"] = q["flow"]
        if sec in ("tls", "reality"):
            p["tls"] = True
            if sni:
                p["servername"] = sni
        if sec == "reality":
            p["reality-opts"] = {"public-key": q.get("pbk", ""), "short-id": q.get("sid", "")}
    else:
        p["password"] = unquote(pu.username or "")
        if sni:
            p["sni"] = sni
    if q.get("fp"):
        p["client-fingerprint"] = q["fp"]
    if q.get("allowInsecure") in ("1", "true") or q.get("insecure") in ("1", "true"):
        p["skip-cert-verify"] = True
    net = q.get("type", "tcp")
    if net == "ws":
        p["network"] = "ws"
        p["ws-opts"] = {"path": unquote(q.get("path", "/")),
                        "headers": {"Host": q.get("host") or sni or pu.hostname}}
    elif net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
    elif net != "tcp":
        return None
    return p


def parse_hy2(u):
    pu = urlparse(u)
    q = {k: v[0] for k, v in parse_qs(pu.query).items()}
    p = {"name": unquote(pu.fragment) or pu.hostname, "type": "hysteria2",
         "server": pu.hostname, "port": pu.port,
         "password": unquote(pu.username or "")}
    if q.get("sni"):
        p["sni"] = q["sni"]
    if q.get("insecure") in ("1", "true"):
        p["skip-cert-verify"] = True
    if q.get("obfs"):
        p["obfs"] = q["obfs"]
        p["obfs-password"] = q.get("obfs-password", "")
    return p


def parse_uri(line):
    try:
        if line.startswith("ss://"):
            return parse_ss(line)
        if line.startswith("vmess://"):
            return parse_vmess(line)
        if line.startswith(("vless://", "trojan://")):
            return parse_vless_trojan(line)
        if line.startswith(("hysteria2://", "hy2://")):
            return parse_hy2(line)
    except Exception:
        return None
    return None


def parse_content(text):
    """支持：Clash yaml / base64 订阅 / 明文链接列表 / 夹带链接的网页(如 Telegram 频道预览)。"""
    text = text.strip()
    if not text:
        return []
    if "proxies:" in text:  # Clash yaml
        try:
            d = yaml.load(text, Loader=YLoader)
            if isinstance(d, dict) and d.get("proxies"):
                return [p for p in d["proxies"] if isinstance(p, dict)]
        except Exception:
            pass
    if "://" not in text:  # base64 订阅（base64 字符表里没有 ':'）
        try:
            text = b64d("".join(text.split())).decode("utf-8", "ignore")
        except Exception:
            return []
    nodes = []
    for u in URI_RE.findall(html.unescape(text)):
        p = parse_uri(u.strip().rstrip(".,;"))
        if p:
            nodes.append(p)
    return nodes


def valid(p):
    try:
        t = p.get("type")
        if t not in SUPPORTED:
            return False
        p["port"] = int(p["port"])
        s = str(p.get("server", ""))
        if not s or not (0 < p["port"] < 65536):
            return False
        if s.startswith(("127.", "0.", "10.", "192.168.")) or s == "localhost":
            return False
        if t in ("vmess", "vless") and not UUID_RE.match(str(p.get("uuid", ""))):
            return False
        if t == "ss" and (p.get("cipher") not in SS_CIPHERS or not p.get("password")):
            return False
        if t in ("trojan", "hysteria2") and not p.get("password"):
            return False
        return True
    except Exception:
        return False


def load_sources():
    """固定来源（可选）：sources.txt + Secret EXTRA_SOURCES。"""
    urls = []
    f = ROOT / "sources.txt"
    if f.exists():
        urls += f.read_text(encoding="utf-8").splitlines()
    urls += os.environ.get("EXTRA_SOURCES", "").splitlines()
    return [u.strip() for u in urls if u.strip() and not u.strip().startswith("#")]


def load_state():
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(state):
    STATE_FILE.parent.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")


def fetch_text(url, limit=8_000_000):
    """流式下载，超过 limit 直接放弃（来源里有不受信任的链接）。"""
    with requests.get(url, timeout=25, stream=True, headers={"User-Agent": "clash.meta"}) as r:
        r.raise_for_status()
        buf, size = [], 0
        for chunk in r.iter_content(65536):
            size += len(chunk)
            if size > limit:
                raise ValueError("too large")
            buf.append(chunk)
        enc = r.encoding or "utf-8"
    return b"".join(buf).decode(enc, "ignore")


def fetch_telegram(url):
    """Telegram 公开频道预览页：翻几页，提取节点；顺便挖出页面里的订阅链接和其他频道。"""
    texts, before = [], None
    for _ in range(TG_PAGES):
        t = fetch_text(url + (f"?before={before}" if before else ""))
        texts.append(t)
        ids = [int(x) for x in re.findall(r'data-post="[^"/]+/(\d+)"', t)]
        if not ids or (before is not None and min(ids) >= before):
            break
        before = min(ids)
    text = "\n".join(texts)
    channels, links = discover.mine_links(text)
    channels.discard(url)
    return parse_content(text), sorted(channels) + sorted(links)


def fetch_one(url):
    """返回 (节点列表, 页面里挖到的新链接列表)。"""
    try:
        if url.startswith("https://t.me/s/"):
            return fetch_telegram(url)
        return parse_content(fetch_text(url)), []
    except Exception:
        return [], []


def node_key(p):
    return (p["type"], p["server"], p["port"], p.get("uuid") or p.get("password"))


def dedupe(pairs):
    """pairs: [(来源url, 节点)]。返回 (去重后节点, {节点key: 出现过的来源集合})。"""
    origin, out = {}, []
    for url, p in pairs:
        if not valid(p):
            continue
        k = node_key(p)
        if k in origin:
            origin[k].add(url)
            continue
        origin[k] = {url}
        out.append(p)
    return out, origin


# =====================================================================
# 2. 测试
# =====================================================================
def tcp_alive(p, timeout=3):
    if p["type"] == "hysteria2":  # UDP 协议，无法用 TCP 预筛
        return True
    try:
        with socket.create_connection((p["server"], p["port"]), timeout=timeout):
            return True
    except Exception:
        return False


def wait_api(proc, secs=20):
    end = time.time() + secs
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            requests.get(f"http://127.0.0.1:{API_PORT}/version", timeout=1)
            return True
        except Exception:
            time.sleep(0.4)
    return False


@contextmanager
def run_mihomo(proxies, listeners=False):
    """启动 mihomo；若某个节点配置非法导致起不来，按报错里的序号剔除后重试。"""
    proxies = list(proxies)
    work = Path(tempfile.mkdtemp(prefix="mihomo-"))
    proc = None
    for _ in range(60):
        cfg = {
            "external-controller": f"127.0.0.1:{API_PORT}",
            "log-level": "info", "mode": "rule", "ipv6": False,
            "proxies": proxies, "rules": ["MATCH,DIRECT"],
        }
        if listeners:
            cfg["listeners"] = [
                {"name": f"in-{p['name']}", "type": "mixed", "listen": "127.0.0.1",
                 "port": LISTEN_BASE + int(p["name"][1:]), "proxy": p["name"]}
                for p in proxies
            ]
        (work / "config.yaml").write_text(
            yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")
        logf = open(work / "mihomo.log", "w+")
        proc = subprocess.Popen([MIHOMO, "-d", str(work), "-f", str(work / "config.yaml")],
                                stdout=logf, stderr=subprocess.STDOUT)
        if wait_api(proc):
            break
        proc.kill()
        proc.wait()
        logf.seek(0)
        text = logf.read()
        m = re.search(r"proxy (\d+):", text)
        if not m or int(m.group(1)) >= len(proxies):
            raise RuntimeError("mihomo 启动失败:\n" + text[-1000:])
        proxies.pop(int(m.group(1)))
    else:
        raise RuntimeError("mihomo 反复启动失败")
    try:
        yield proxies
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except Exception:
            proc.kill()


def delay_of(name):
    try:
        r = requests.get(f"http://127.0.0.1:{API_PORT}/proxies/{name}/delay",
                         params={"url": DELAY_URL, "timeout": 5000}, timeout=8)
        return r.json().get("delay") if r.status_code == 200 else None
    except Exception:
        return None


def probe(port):
    """通过节点访问 Cloudflare：拿出口国家 + 测下载速度(MB/s)。"""
    px = {"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"}
    try:
        t = requests.get(TRACE_URL, proxies=px, timeout=8).text
        cc = re.search(r"loc=(\w+)", t).group(1)
    except Exception:
        return None
    got, t0 = 0, time.time()
    try:
        with requests.get(SPEED_URL, proxies=px, timeout=10, stream=True) as r:
            for chunk in r.iter_content(65536):
                got += len(chunk)
                if time.time() - t0 > SPEED_SECS:
                    break
    except Exception:
        pass
    el = max(time.time() - t0, 0.001)
    return cc, got / el / 1e6


# =====================================================================
# 3. 生成 Clash 配置
# =====================================================================
def flag(cc):
    if len(cc) == 2 and cc.isalpha():
        return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper())
    return "🏳️"


def build_config(nodes, cc_of):
    names = [n["name"] for n in nodes]
    by_cc = {}
    for n in nodes:
        by_cc.setdefault(cc_of[n["name"]], []).append(n["name"])
    country_groups = [
        {"name": f"{flag(cc)} {CN_NAME.get(cc, cc)}", "type": "url-test", "url": DELAY_URL,
         "interval": 300, "tolerance": 50, "proxies": v}
        for cc, v in sorted(by_cc.items(), key=lambda kv: -len(kv[1]))
    ]
    groups = [
        {"name": "🚀 节点选择", "type": "select",
         "proxies": ["♻️ 自动选择", "🔯 故障转移", "🖐 手动选择",
                     *[g["name"] for g in country_groups], "DIRECT"]},
        {"name": "♻️ 自动选择", "type": "url-test", "url": DELAY_URL,
         "interval": 300, "tolerance": 50, "proxies": names},
        {"name": "🔯 故障转移", "type": "fallback", "url": DELAY_URL,
         "interval": 300, "proxies": names},
        {"name": "🖐 手动选择", "type": "select", "proxies": names},
        *country_groups,
    ]
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "unified-delay": True,
        "tcp-concurrent": True,
        "profile": {"store-selected": True},
        "dns": {
            "enable": True, "ipv6": False, "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "fake-ip-filter": ["*.lan", "+.local", "+.msftconnecttest.com",
                               "+.msftncsi.com", "localhost.ptlogin2.qq.com"],
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
            "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
            "nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
            "fallback": ["https://1.1.1.1/dns-query#🚀 节点选择",
                         "https://8.8.8.8/dns-query#🚀 节点选择"],
            "fallback-filter": {"geoip": True, "geoip-code": "CN",
                                "ipcidr": ["240.0.0.0/4"]},
        },
        "proxies": nodes,
        "proxy-groups": groups,
        "rules": [
            "GEOSITE,private,DIRECT",
            "GEOIP,private,DIRECT,no-resolve",
            "GEOSITE,category-ads-all,REJECT",
            "GEOSITE,cn,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 节点选择",
        ],
    }


# =====================================================================
# main
# =====================================================================
def main():
    t0 = time.time()
    static = load_sources()
    state = load_state()
    known = [u for u, v in state.items() if v.get("dead", 0) < DEAD_LIMIT]
    found = discover.discover() if os.environ.get("DISCOVER", "1") != "0" else []
    srcs = list(dict.fromkeys(static + known + found))
    if not srcs:
        sys.exit("没有任何来源：自动发现没找到候选文件，且没有固定来源/历史来源")
    log(f"来源：固定 {len(static)} + 历史有效 {len(known)} + 本轮发现 {len(found)}，去重后 {len(srcs)} 个")

    with cf.ThreadPoolExecutor(16) as ex:
        results = list(ex.map(fetch_one, srcs))
        # 第二轮：Telegram 频道里挖出来的订阅链接 / 其他频道
        extra = list(dict.fromkeys(l for _, links in results for l in links if l not in srcs))
        extra = random.sample(extra, min(len(extra), discover.MAX_LINKS))
        if extra:
            results += list(ex.map(fetch_one, extra))
            srcs = srcs + extra
            log(f"第二轮：从 Telegram 页面里又挖到 {len(extra)} 个链接")
    fetched = [ns for ns, _ in results]
    pairs = [(u, p) for u, ns in zip(srcs, fetched) for p in ns]
    nodes, origin = dedupe(pairs)
    log(f"解析 {len(pairs)} 个，去重/校验后 {len(nodes)} 个，有产出的来源 {sum(1 for n in fetched if n)} 个")

    random.shuffle(nodes)
    nodes = nodes[:MAX_PREFILTER]
    with cf.ThreadPoolExecutor(300) as ex:
        nodes = [p for p, ok in zip(nodes, ex.map(tcp_alive, nodes)) if ok]
    log(f"TCP 预筛后 {len(nodes)} 个")
    if not nodes:
        sys.exit("没有存活节点，保留上一次的输出")
    nodes = nodes[:MAX_CANDIDATES]

    # ---- 延迟测试 ----
    for i, p in enumerate(nodes):
        p["name"] = f"n{i}"
    with run_mihomo(nodes) as kept:
        with cf.ThreadPoolExecutor(64) as ex:
            ds = list(ex.map(lambda p: delay_of(p["name"]), kept))
    alive = sorted([(d, p) for d, p in zip(ds, kept) if d and d <= MAX_DELAY_MS], key=lambda x: x[0])
    log(f"延迟测试通过 {len(alive)} / {len(kept)}")
    if not alive:
        sys.exit("没有节点通过延迟测试，保留上一次的输出")
    top = [p for _, p in alive[:SPEED_TOP]]

    # ---- 来源评分：只要有节点通过延迟测试，就算这个来源有效 ----
    credit = {}
    for _, p in alive:
        for u in origin.get(node_key(p), ()):
            credit[u] = credit.get(u, 0) + 1
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    for u in srcs:
        if credit.get(u):
            state[u] = {"dead": 0, "alive": credit[u], "last_ok": stamp}
        elif u in state:
            state[u]["dead"] = state[u].get("dead", 0) + 1
    state = {u: v for u, v in state.items() if v.get("dead", 0) < DEAD_LIMIT}
    if len(state) > MAX_STATE:
        state = dict(sorted(state.items(), key=lambda kv: -kv[1].get("alive", 0))[:MAX_STATE])
    save_state(state)

    # ---- 测速 + 出口国家 ----
    for i, p in enumerate(top):
        p["name"] = f"n{i}"
    with run_mihomo(top, listeners=True) as kept:
        with cf.ThreadPoolExecutor(8) as ex:
            res = list(ex.map(lambda p: probe(LISTEN_BASE + int(p["name"][1:])), kept))
        results = [(p, r) for p, r in zip(kept, res) if r]
    log(f"测速完成 {len(results)} 个可出网")

    results.sort(key=lambda x: -x[1][1])
    final, cnt = [], {}
    for p, (cc, spd) in results:
        if spd < MIN_SPEED or cnt.get(cc, 0) >= PER_COUNTRY:
            continue
        cnt[cc] = cnt.get(cc, 0) + 1
        final.append((p, cc, spd))
        if len(final) >= KEEP:
            break
    if not final:
        sys.exit("没有节点达到最低速度，保留上一次的输出")

    # ---- 命名 & 输出 ----
    idx, cc_of, out_nodes = {}, {}, []
    for p, cc, spd in final:
        idx[cc] = idx.get(cc, 0) + 1
        p["name"] = f"{flag(cc)} {cc}-{idx[cc]:02d} {spd:.1f}MB/s"
        cc_of[p["name"]] = cc
        out_nodes.append(p)

    OUT.mkdir(exist_ok=True)
    cfg = build_config(out_nodes, cc_of)
    dump = lambda d: yaml.safe_dump(d, allow_unicode=True, sort_keys=False, width=1000)
    (OUT / "clash.yaml").write_text(f"# updated: {stamp}\n" + dump(cfg), encoding="utf-8")
    (OUT / "proxies.yaml").write_text(f"# updated: {stamp}\n" + dump({"proxies": out_nodes}), encoding="utf-8")
    (OUT / "status.json").write_text(json.dumps({
        "updated": stamp, "sources": len(srcs), "sources_with_nodes": sum(1 for n in fetched if n),
        "sources_alive": len(credit), "parsed": len(pairs), "after_dedupe": len(nodes),
        "delay_ok": len(alive), "final": len(out_nodes), "countries": cnt,
        "seconds": round(time.time() - t0),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    log(f"完成：{len(out_nodes)} 个节点，国家分布 {cnt}，耗时 {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()

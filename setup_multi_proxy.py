#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""多订阅实时优选代理：拉取订阅 -> 解析节点 -> 并发测速 -> 生成 sing-box 配置并启动。

替代上游单一节点的 setup_proxy.sh。差别只有一处：它把 NODE_LINK 一个节点写进
sing-box，这里把多个订阅里的全部可用节点写进去，先实测连通性再按延迟排序，
交给 sing-box 的 urltest 自动切换。

环境变量：
  SUB_URLS     订阅链接，一行一个（必填）
  TOP_N        进入 urltest 的节点数上限，默认 8
  TEST_TIMEOUT 单节点测速超时秒数，默认 5
  TEST_WORKERS 并发测速线程数，默认 64
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

SUB_URLS = [line.strip() for line in os.environ.get("SUB_URLS", "").splitlines() if line.strip()]
TOP_N = int(os.environ.get("TOP_N", "8"))
TEST_TIMEOUT = float(os.environ.get("TEST_TIMEOUT", "5"))
TEST_WORKERS = int(os.environ.get("TEST_WORKERS", "64"))
CONFIG_PATH = Path("sing-box-config.json")
LOG_PATH = Path("sing-box.log")
# 订阅里常混着这类条目，它们不是节点。
SKIP_SCHEMES = {"https", "http", "ssr", "socks4", "ftp"}


def log(message: str) -> None:
    print("[multi-proxy] " + message, flush=True)


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "sing-box/1.10"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8", "replace")


def subscription_links(text: str) -> list[str]:
    """订阅内容是逐行分享链接，或整段 base64。"""
    stripped = text.strip()
    if "://" in stripped[:300]:
        return [line.strip() for line in stripped.splitlines() if "://" in line]
    try:
        padded = stripped + "=" * (-len(stripped) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", "replace")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return []
    return [line.strip() for line in decoded.splitlines() if "://" in line]


def truthy(value: str | None) -> bool:
    return str(value or "").lower() in {"1", "true", "yes"}


def base_tls(params: dict) -> dict:
    security = (params.get("security", ["none"])[0] or "none").lower()
    tls: dict = {"enabled": security in {"tls", "reality"}}
    sni = params.get("sni", [""])[0] or params.get("host", [""])[0]
    if sni:
        tls["server_name"] = sni
    if truthy(params.get("allowInsecure", [""])[0]) or truthy(params.get("insecure", [""])[0]):
        tls["insecure"] = True
    fingerprint = params.get("fp", [""])[0]
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if security == "reality":
        tls["reality"] = {
            "enabled": True,
            "public_key": params.get("pbk", [""])[0],
            "short_id": params.get("sid", [""])[0],
        }
    return tls


def transport_of(params: dict) -> dict | None:
    kind = (params.get("type", ["tcp"])[0] or "tcp").lower()
    if kind in {"tcp", "raw"}:
        return None
    # sing-box 不支持 xhttp（xray 特有），交给调用方跳过
    if kind == "xhttp":
        return {"__unsupported__": "xhttp"}
    headers = {}
    host = params.get("host", [""])[0]
    if host:
        headers["Host"] = host
    path = unquote(params.get("path", ["/"])[0] or "/")
    if kind == "ws":
        result = {"type": "ws", "path": path}
        if headers:
            result["headers"] = headers
        return result
    if kind == "grpc":
        return {"type": "grpc", "service_name": params.get("serviceName", [""])[0]}
    if kind == "httpupgrade":
        result = {"type": "httpupgrade", "path": path}
        if host:
            result["host"] = host
        return result
    if kind == "http":
        return {"type": "http", "path": path, "host": [host] if host else []}
    return {"__unsupported__": kind}


def parse_node(link: str) -> dict | None:
    """把一条分享链接转成 sing-box outbound，不支持的返回 None。"""
    scheme = link.split("://", 1)[0].lower()
    if scheme in SKIP_SCHEMES:
        return None
    try:
        if scheme == "vmess":
            payload = link.split("://", 1)[1].split("#", 1)[0]
            payload += "=" * (-len(payload) % 4)
            obj = json.loads(base64.b64decode(payload).decode("utf-8", "replace"))
            transport = None
            net = (obj.get("net") or "tcp").lower()
            if net in {"ws", "grpc", "http", "httpupgrade"}:
                transport = {"type": net}
                if net in {"ws", "httpupgrade"}:
                    transport["path"] = obj.get("path") or "/"
                if net == "grpc":
                    transport["service_name"] = obj.get("path") or ""
                if obj.get("host"):
                    if net in {"ws", "httpupgrade"}:
                        transport["headers"] = {"Host": obj["host"]}
                    elif net == "http":
                        transport["host"] = [obj["host"]]
            elif net == "xhttp":
                return None
            outbound = {
                "type": "vmess", "tag": "", "server": obj.get("add", ""),
                "server_port": int(obj.get("port") or 443), "uuid": obj.get("id", ""),
                "security": obj.get("scy") or "auto", "alter_id": int(obj.get("aid") or 0),
            }
            tls_enabled = (obj.get("tls") or "").lower() in {"tls", "reality"}
            outbound["tls"] = {"enabled": tls_enabled}
            if tls_enabled:
                sni = obj.get("sni") or obj.get("host") or obj.get("add")
                if sni:
                    outbound["tls"]["server_name"] = sni
                if obj.get("fp"):
                    outbound["tls"]["utls"] = {"enabled": True, "fingerprint": obj["fp"]}
            if transport:
                outbound["transport"] = transport
            return outbound

        parts = urlsplit(link)
        params = parse_qs(parts.query)
        userinfo = unquote(parts.username or "")
        password = unquote(parts.password or "")
        host = parts.hostname or ""
        port = int(parts.port or 443)
        if not host or not port:
            return None

        if scheme == "vless":
            outbound = {"type": "vless", "tag": "", "server": host, "server_port": port,
                        "uuid": userinfo}
            flow = params.get("flow", [""])[0]
            if flow:
                outbound["flow"] = flow
            outbound["tls"] = base_tls(params)
            transport = transport_of(params)
            if transport and "__unsupported__" in transport:
                return None
            if transport:
                outbound["transport"] = transport
            return outbound

        if scheme == "trojan":
            outbound = {"type": "trojan", "tag": "", "server": host, "server_port": port,
                        "password": userinfo or password}
            outbound["tls"] = base_tls(params)
            transport = transport_of(params)
            if transport and "__unsupported__" in transport:
                return None
            if transport:
                outbound["transport"] = transport
            return outbound

        if scheme in {"ss", "shadowsocks"}:
            raw = link.split("://", 1)[1].split("#", 1)[0]
            raw = raw.split("?", 1)[0]
            if "@" in raw:
                method_password = unquote(raw.rsplit("@", 1)[0])
            else:
                padded = raw + "=" * (-len(raw) % 4)
                method_password = base64.b64decode(padded).decode("utf-8", "replace")
            method, _, secret = method_password.partition(":")
            return {"type": "shadowsocks", "tag": "", "server": host, "server_port": port,
                    "method": method, "password": secret}

        if scheme == "hysteria2" or scheme == "hy2":
            outbound = {"type": "hysteria2", "tag": "", "server": host, "server_port": port,
                        "password": userinfo or password}
            sni = params.get("sni", [""])[0]
            if sni:
                outbound["tls"] = {"enabled": True, "server_name": sni,
                                   "insecure": truthy(params.get("insecure", [""])[0])}
            obfs = params.get("obfs", [""])[0]
            obfs_password = params.get("obfs-password", [""])[0]
            if obfs == "salamander" and obfs_password:
                outbound["obfs"] = {"type": "salamander", "password": obfs_password}
            return outbound

        if scheme == "anytls":
            outbound = {"type": "anytls", "tag": "", "server": host, "server_port": port,
                        "password": userinfo or password}
            outbound["tls"] = base_tls(params)
            return outbound

        if scheme == "socks5" or scheme == "socks":
            outbound = {"type": "socks", "tag": "", "server": host, "server_port": port,
                        "version": "5"}
            if userinfo:
                outbound["username"] = userinfo
            if password:
                outbound["password"] = password
            return outbound
    except Exception:
        return None
    return None


def latency(outbound: dict) -> float | None:
    """TCP 建连延迟，用作可用性判据。"""
    started = time.monotonic()
    try:
        with socket.create_connection((outbound["server"], outbound["server_port"]),
                                      timeout=TEST_TIMEOUT):
            return time.monotonic() - started
    except OSError:
        return None


def main() -> int:
    if not SUB_URLS:
        log("没有配置 SUB_URLS，退回直连模式")
        with open(os.environ.get("GITHUB_ENV", "/dev/null"), "a", encoding="utf-8") as handle:
            handle.write("IS_PROXY=false\n")
        return 0

    links: list[str] = []
    for url in SUB_URLS:
        try:
            text = fetch(url)
        except Exception as exc:
            log("订阅拉取失败 %s: %s" % (url.split("?")[0][:40], exc))
            continue
        found = subscription_links(text)
        links.extend(found)
        log("订阅 %s -> %d 条" % (url.split("?")[0][:40], len(found)))

    seen: set[tuple] = set()
    nodes: list[dict] = []
    for link in links:
        node = parse_node(link)
        if not node:
            continue
        key = (node["server"], node["server_port"], node["type"])
        if key in seen:
            continue
        seen.add(key)
        node["tag"] = "%s-%s" % (node["type"], len(nodes))
        nodes.append(node)
    log("去重后可用节点: %d 个" % len(nodes))
    if not nodes:
        log("没有解析出任何节点")
        return 1

    with ThreadPoolExecutor(max_workers=TEST_WORKERS) as pool:
        results = list(pool.map(lambda item: (latency(item), item), nodes))

    alive = [(value, node) for value, node in results if value is not None]
    alive.sort(key=lambda pair: pair[0])
    log("连通 %d/%d 个，最快 %s" % (
        len(alive), len(nodes),
        ", ".join("%s %.0fms" % (node["tag"], seconds * 1000) for seconds, node in alive[:5])
        or "(无)"))

    picked = [node for _, node in alive[:TOP_N]]
    if not picked:
        log("没有节点能连通，退回直连")
        with open(os.environ.get("GITHUB_ENV", "/dev/null"), "a", encoding="utf-8") as handle:
            handle.write("IS_PROXY=false\n")
        return 1

    config = {
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080},
            {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": 1081},
        ],
        "outbounds": picked + [
            {"type": "urltest", "tag": "auto",
             "outbounds": [node["tag"] for node in picked],
             "url": "https://www.gstatic.com/generate_204",
             "interval": "1m", "tolerance": 100},
            {"type": "selector", "tag": "proxy",
             "outbounds": ["auto"] + [node["tag"] for node in picked],
             "default": "auto"},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": "proxy"},
    }
    CONFIG_PATH.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    log("已生成 %s（%d 个节点进 urltest）" % (CONFIG_PATH, len(picked)))

    subprocess.run(["pkill", "-f", "sing-box"], check=False)
    with open(LOG_PATH, "wb") as output:
        process = subprocess.Popen(["./sing-box", "run", "-c", str(CONFIG_PATH)],
                                   stdout=output, stderr=subprocess.STDOUT)
    time.sleep(5)
    if process.poll() is not None:
        log("sing-box 启动失败:\n" + LOG_PATH.read_text(encoding="utf-8", errors="replace")[-1500:])
        return 1

    for attempt in range(1, 4):
        probe = subprocess.run(
            ["curl", "-x", "socks5://127.0.0.1:1080", "-s", "--max-time", "15",
             "https://api.ipify.org"],
            capture_output=True, text=True)
        if probe.returncode == 0 and probe.stdout.strip():
            log("代理连通，出口 IP: %s" % probe.stdout.strip())
            with open(os.environ.get("GITHUB_ENV", "/dev/null"), "a", encoding="utf-8") as handle:
                handle.write("IS_PROXY=true\nPROXY_SERVER=socks5://127.0.0.1:1080\n")
            return 0
        log("代理探测第 %d/3 次失败，重试" % attempt)
        time.sleep(3)

    log("代理探测三次均失败:\n" + LOG_PATH.read_text(encoding="utf-8", errors="replace")[-1500:])
    return 1


if __name__ == "__main__":
    sys.exit(main())


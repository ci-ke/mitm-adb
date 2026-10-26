#!/usr/bin/env python3
"""
抓取虚拟机 / 物理平板的流量，本地起 mitmweb 界面，并对特定响应做解密展示。

用法:
    uv sync
    cp .env.example .env   # 填上 DECRYPT_KEY / DECRYPT_IV
    uv run main.py --list                       # 先看设备序列号（USB 插着才有）
    uv run main.py 10.1.162.244:6556            # 虚拟机（局域网，adbd 固定 6556）
    uv run main.py 192.168.1.23:37015           # 物理平板（无线调试）
    uv run main.py R58M1234AB --emudhra         # 物理平板（USB 直连，免装证书）
    uv run main.py R58M1234AB:6556              # 虚拟机（经物理平板 USB 转发，不依赖网络）

三层可见性，逐层收窄（decrypt ⊆ probe ⊆ capture）:
    capture  记录谁——命中的连接都会出现在列表里。没被换证书的只有一条 TCP 记录，
             能看到 host:port 和连接时间，内容仍是密文。
    probe    其中谁换证书——只有这些看得到明文，才有机会解密。
    decrypt  其中谁再解一层——AES 解出可读副本。
    所以 PROBE_HOSTS 留空就是纯侦察模式：什么都不换证书，设备完全不受打扰，
    列表里照样能看到这台设备都连了哪些域名。先跑一轮看清单，再挑目标填进
    PROBE_HOSTS 就能看明文了。

配置:
    密钥等敏感信息只放在本目录的 .env（已在 .gitignore 里，不入库），模板见 .env.example。
    以下都可用同名真实环境变量覆盖（环境变量优先级更高）:
        DECRYPT_KEY      AES-128 密钥，16 字节
        DECRYPT_IV       AES-128 IV，16 字节
        CAPTURE_HOSTS    记录谁，默认 *（全记）
        CAPTURE_IGNORE   连记录都不要
        PROBE_HOSTS      换证书谁，留空 = 纯侦察
        PROBE_IGNORE     不换证书，但仍留一条 TCP 记录
        DECRYPT_HOSTS    解密谁，留空 = 跟 PROBE_HOSTS 一样
        DECRYPT_IGNORE   只看明文，不解包

    六份名单写法一致（代码里不内置任何域名，全部来自 .env）:
        *               全部
        .example.com    这个域连同所有子域
        api.example.com 只匹配这一条主机名
    .env 缺失或缺密钥时，脚本照常抓包，只是自动关掉响应解密。

它会做这几件事:
    1. 连设备：<ip>:<端口> 直接 adb connect；只写序列号 = USB 直连；
       写 <序列号>:<端口> = 先经该 USB 设备把端口转发到本机回环，再 connect 回环地址
    2. adb reverse tcp:8080 tcp:8080  （设备本地 8080 → PC 的 8080，走 adb 隧道）
    3. 把设备全局代理指向 127.0.0.1:8080
    4. 启动 mitmweb，浏览器界面在 http://127.0.0.1:8081
    5. Ctrl+C 退出时自动还原代理、撤销隧道

免装证书（--emudhra）:
    默认情况下设备必须信任 mitmproxy 自己的 CA（虚拟机里可以 cp 进系统目录，物理平板没 root 做不到）。
    加上 --emudhra 后改用 mitmproxy 内置的 eMudhra 泄露中间 CA 私钥现场签发：
    叶证书 → EM OV TLS CA - G3C →（Sectigo 交叉签名）→ AAA Certificate Services，
    这条根是设备出厂就信任的，所以**不需要往设备装任何证书**。
    代价是只有这里签的域名能被解密，所以同时只会对 PROBE_HOSTS 里的域名换证书，
    其余流量原样隧道直通（别的 App 不会因为证书不受信而报错）。
    另外 SDK / 埋点类端点客户端自带证书校验（pin 或自带信任库），一旦探针到就会在
    握手中被拒，把这些域名写进 PROBE_IGNORE 放行，让它们直接连真服务器。

响应解密:
    请求体与响应体都是 AES-128-CBC(msgpack)。解出的明文会以「副本」形式注入 Web UI，
    原 flow 不变，客户端与服务器之间的字节完全不受影响。用 --no-decrypt 可关闭。

稀有素材标记:
    解出的 JSON 里若带 updatedResources.userMysekaiHarvestMaps，会扫一遍掉落物，
    命中预设的几种稀有素材时，该条 flow 的标记变成「🔴编号」，
    并在红圈左边显示素材图标（webui/hits.js 注入 mitmweb 前端）。

不落盘，不写 flows 文件。
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from secrets import token_hex
from typing import TYPE_CHECKING, Any, NoReturn, TypedDict, cast

import msgpack  # type: ignore[import-untyped]  # 上游没带 py.typed
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from dotenv import load_dotenv

if TYPE_CHECKING:
    from types import ModuleType

    import mitmproxy.http as http
    import mitmproxy.options as options
    import mitmproxy.tcp as tcp


# mitmproxy 11 起 ctx.log 已弃用，官方建议直接用标准 logging。
# 注意：mitmweb 只把 WARNING 以上放行到根 logger（mitmproxy 自带的 CLI 才会把根
# logger 调到 DEBUG），所以 info 级别必须在本 logger 上显式定级，否则会被静默吞掉。
logger = logging.getLogger("mitm-adb")
logger.setLevel(logging.INFO)


# --------------------------------------------------------------------------
# 响应解密
# --------------------------------------------------------------------------

# 敏感配置一律来自本目录的 .env（模板见 .env.example），脚本里不再写任何密钥。
ENV_FILE: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")

# AES-128-CBC 的 key/iv 长度都是 16 字节
AES_KEY_LEN: int = 16

# 域名规则一律写在 .env 里（PROBE_HOSTS / PROBE_IGNORE / DECRYPT_HOSTS），
# 代码里不内置任何域名——换游戏、换服只要改配置，不用动脚本。

# 解密副本在列表里显示的标记（mitmweb 会渲染在 Path 列）
MARKER: str = "[dec]"


@dataclass(frozen=True)
class DecryptSecrets:
    """从 .env 读出的加解密参数。"""

    key: bytes
    iv: bytes


def load_env(env_file: str = ENV_FILE) -> None:
    """把 .env 灌进 os.environ。

    override=False：已经存在的真实环境变量优先，方便临时用 DECRYPT_KEY=... 覆盖，
    CI 里也不必生成 .env 文件。
    """
    if not os.path.isfile(env_file):
        print(f"[配置] 没找到 {env_file}，只用真实环境变量（模板见 .env.example）")
        return
    load_dotenv(env_file, override=False, encoding="utf-8")


def _read_secret(name: str) -> bytes | None:
    """读一项 16 字节的参数字节；缺失或长度不对时返回 None 并说明原因。"""
    raw = os.environ.get(name, "").strip()
    if not raw:
        print(f"[配置] {name} 未设置")
        return None
    value = raw.encode("utf-8")
    if len(value) != AES_KEY_LEN:
        print(f"[配置] {name} 必须是 {AES_KEY_LEN} 字节，当前 {len(value)} 字节")
        return None
    return value


def load_secrets() -> DecryptSecrets | None:
    """key 与 iv 都合法才返回；否则返回 None（等同于不启用解密）。"""
    key = _read_secret("DECRYPT_KEY")
    iv = _read_secret("DECRYPT_IV")
    if key is None or iv is None:
        print("[配置] 没有可用的密钥 -> 本次不启用响应解密（模板见 .env.example）")
        return None
    return DecryptSecrets(key=key, iv=iv)


def _split_hosts(raw: str) -> tuple[str, ...]:
    """逗号分隔的域名清单 -> 元组（去空项、统一小写）。"""
    return tuple(h.strip().lower() for h in raw.split(",") if h.strip())


def host_matches(host: str, entry: str) -> bool:
    """一条规则怎么匹配一个主机名。

        *              全抓
        .example.com   这个域及其所有子域
        a.b.com        只匹配这一条

    只比主机名本身：路径、查询串、端口都不在这个字符串里。
    """
    host = host.strip().lower()
    entry = entry.strip().lower()
    if entry == "*":
        return True
    if entry.startswith("."):
        return host == entry[1:] or host.endswith(entry)
    return host == entry


def host_patterns(hosts: tuple[str, ...]) -> list[str]:
    """把域名规则转成 mitmproxy 的 host 正则（allow_hosts / ignore_hosts 共用，按 host:port 匹配）。"""
    out: list[str] = []
    for raw in hosts:
        entry = raw.strip().lower()
        if not entry:
            continue
        if entry == "*":
            out.append(r".*")
        elif entry.startswith("."):
            out.append(rf"(?:^|\.){re.escape(entry[1:])}:\d+$")
        else:
            out.append(rf"^{re.escape(entry)}:\d+$")
    return out


def _warn_non_host_entries(name: str, hosts: tuple[str, ...]) -> None:
    """名单只认主机名：带路径 / 查询串 / 端口的条目永远匹配不上，提前喊一声。

    mitmproxy 判定 allow/ignore 时还没解析 HTTP，手上只有 SNI、Host 头和
    「主机:端口」，路径和查询串根本不存在，所以这些字符写进去必然是死规则。
    """
    for entry in hosts:
        if any(ch in entry for ch in "/?#: "):
            print(
                f"[配置] {name} 里的 {entry} 带了路径 / 查询串 / 端口，永远匹配不上——"
                "这里只写主机名（端口由脚本自动补）；按路径过滤请用 mitmweb 的过滤框"
            )


@dataclass(frozen=True)
class HostRules:
    """三层，自上而下逐层收窄：decrypt ⊆ probe ⊆ capture。

        capture  记录谁——命中的连接都会出现在列表里
        probe    其中谁换证书——只有这些看得到明文
        decrypt  其中谁再解一层——AES 解出可读副本

    每层都配一条 ignore 做例外：
        capture_ignore  连记录都不留（连 capture 都进不来）
        probe_ignore    不换证书，但留一条 TCP 记录（还在 capture 里）
        decrypt_ignore  能看到明文，但不去解包（还在 probe 里）

    mitmproxy 本身只有 allow/ignore 一对判定，capture 这层是靠 show_ignored_hosts
    把隧道连接也记下来、再按 capture 名单裁剪实现的（见 TunnelRecorder）。
    """

    capture: tuple[str, ...]
    capture_ignore: tuple[str, ...]
    probe: tuple[str, ...]
    probe_ignore: tuple[str, ...]
    decrypt: tuple[str, ...]
    decrypt_ignore: tuple[str, ...]

    @staticmethod
    def _matches(entries: tuple[str, ...], host: str) -> bool:
        return any(host_matches(host, e) for e in entries)

    def allow_patterns(self) -> list[str]:
        """给 mitmproxy 的 allow_hosts：命中才换证书。"""
        if not self.probe:
            # allow_hosts 为空时 mitmproxy 会当成"没有限制"从而全拦，
            # 纯侦察模式必须给一条永不匹配的规则，让所有连接都落到隧道分支。
            return [r"(?!)"]
        return host_patterns(self.probe)

    def ignore_patterns(self) -> list[str]:
        """给 mitmproxy 的 ignore_hosts：命中的一律走隧道。

        capture_ignore 和 probe_ignore 在这里合成一个集合，区别在事后：
        probe_ignore 留一条 TCP 记录，capture_ignore 连这条也要删掉。
        """
        return host_patterns(self.capture_ignore + self.probe_ignore)

    def should_record(self, host: str) -> bool:
        """这条连接要不要出现在列表里。"""
        return self._matches(self.capture, host) and not self._matches(
            self.capture_ignore, host
        )

    def should_decrypt(self, host: str) -> bool:
        """这条连接要不要尝试解密。"""
        return self._matches(self.decrypt, host) and not self._matches(
            self.decrypt_ignore, host
        )


def _covered(entry: str, by: tuple[str, ...]) -> bool:
    """entry 这条规则是否被 by 这组规则整体覆盖（用于检查子集关系）。"""
    if "*" in by:
        return True
    bare = entry[1:] if entry.startswith(".") else entry
    return any(host_matches(bare, b) for b in by)


def _check_subset(lower: str, lower_hosts: tuple[str, ...], upper: str, upper_hosts: tuple[str, ...]) -> None:
    """下层名单里出现了上层没覆盖的域名时提醒一句——那不是错误，但肯定是配置写歪了。"""
    for entry in lower_hosts:
        if not _covered(entry, upper_hosts):
            print(
                f"[配置] {lower} 里的 {entry} 不在 {upper} 范围内，"
                f"实际不会生效（{upper} 决定这一层的上限）"
            )


def load_host_rules() -> HostRules:
    """从环境变量（.env）读六份名单，代码里不内置任何域名。

        CAPTURE_HOSTS / CAPTURE_IGNORE   记录谁 / 连记录都不要
        PROBE_HOSTS   / PROBE_IGNORE     换证书谁 / 不换证书但留记录
        DECRYPT_HOSTS / DECRYPT_IGNORE   解密谁 / 只看明文不解包

    CAPTURE_HOSTS 缺省即 `*`（全记）；PROBE_HOSTS 留空 = 纯侦察，什么都不换证书；
    DECRYPT_HOSTS 留空 = 跟 PROBE_HOSTS 一样。

    六份名单都只写主机名，不能带路径、查询串或端口——mitmproxy 判定 allow/ignore
    时还没解析 HTTP，路径根本不存在；端口由 host_patterns() 自动补。
    """
    capture = _split_hosts(os.environ.get("CAPTURE_HOSTS", "")) or ("*",)
    capture_ignore = _split_hosts(os.environ.get("CAPTURE_IGNORE", ""))
    probe = _split_hosts(os.environ.get("PROBE_HOSTS", ""))
    probe_ignore = _split_hosts(os.environ.get("PROBE_IGNORE", ""))
    decrypt = _split_hosts(os.environ.get("DECRYPT_HOSTS", "")) or probe
    decrypt_ignore = _split_hosts(os.environ.get("DECRYPT_IGNORE", ""))

    for name, entries in (
        ("CAPTURE_HOSTS", capture),
        ("CAPTURE_IGNORE", capture_ignore),
        ("PROBE_HOSTS", probe),
        ("PROBE_IGNORE", probe_ignore),
        ("DECRYPT_HOSTS", decrypt),
        ("DECRYPT_IGNORE", decrypt_ignore),
    ):
        _warn_non_host_entries(name, entries)

    _check_subset("PROBE_HOSTS", probe, "CAPTURE_HOSTS", capture)
    _check_subset("DECRYPT_HOSTS", decrypt, "PROBE_HOSTS", probe)

    return HostRules(
        capture=capture,
        capture_ignore=capture_ignore,
        probe=probe,
        probe_ignore=probe_ignore,
        decrypt=decrypt,
        decrypt_ignore=decrypt_ignore,
    )


def _describe(hosts: tuple[str, ...], ignore: tuple[str, ...]) -> str:
    """横幅里一行显示一层名单：主名单 + 排除项。"""
    text = "、".join(hosts) or "（空）"
    if ignore:
        text += "    排除 " + "、".join(ignore)
    return text


# --------------------------------------------------------------------------
# 稀有素材（updatedResources.userMysekaiHarvestMaps）
# --------------------------------------------------------------------------

# 掉落物 resourceType == "mysekai_material" 且 resourceId 命中这四样就报出来。
# id 与图标取自 master 数据（iconAssetbundleName），图标文件已复制到 webui/icon/。
RARE_MATERIALS: dict[int, tuple[str, str]] = {
    12: ("钻石", "item_mineral_7.png"),
    20: ("四叶草", "item_plant_1.png"),
    5: ("夕桐", "item_wood_5.png"),
    24: ("空白的音色", "item_tone_8.png"),
}

# 场景 id → 名字（取自 master 的 sites 表）
SITE_NAMES: dict[int, str] = {5: "初始空地", 6: "心愿沙滩", 7: "烂漫花田", 8: "忘却之所"}

# 前端注入资源所在目录（hits.js / hits.css / icon/）
WEBUI_DIR: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "webui")


class MaterialItem(TypedDict):
    """单个素材条目，webui/hits.js 按这几个字段渲染图标与浮层。"""

    name: str
    icon: str
    count: int
    where: str


class Hit(TypedDict):
    """一次命中：哪条请求、什么时候、掉了什么。"""

    path: str
    time: str
    items: list[MaterialItem]


class HitRecord(TypedDict):
    """同一种素材在一份响应里的汇总（sites 的 key 是 msgpack 里的 siteId，通常是 int）。"""

    count: int
    sites: dict[Any, int]


# 命中登记表：编号 -> Hit，由 webui/hits.js 拉取
HITS: dict[str, Hit] = {}
_hit_seq: int = 0
_webui_installed: bool = False


def _split_harvest_map(entry: Any) -> tuple[Any, list[Any]]:
    """harvest map 有两种编码：旧版 dict，现行版 [siteId, fixtures, drops]。"""
    if isinstance(entry, dict):
        drops = entry.get("userMysekaiSiteHarvestResourceDrops")
        return entry.get("mysekaiSiteId"), drops if isinstance(drops, list) else []
    if isinstance(entry, (list, tuple)) and len(entry) >= 3:
        drops = entry[2]
        return entry[0], list(drops) if isinstance(drops, (list, tuple)) else []
    return None, []


def _split_drop(drop: Any) -> tuple[Any, Any, float]:
    """掉落物同样两种编码：dict 或 [type, id, x, z, ..., quantity(7), ...]。"""
    if isinstance(drop, dict):
        return drop.get("resourceType"), drop.get("resourceId"), drop.get("quantity", 1)
    if isinstance(drop, (list, tuple)) and len(drop) >= 2:
        qty = drop[7] if len(drop) > 7 else 1
        return drop[0], drop[1], qty
    return None, None, 0


def scan_harvest_maps(obj: Any) -> dict[int, HitRecord] | None:
    """扫一遍 harvest map 里的掉落物。

    返回 None  -> 这份 JSON 没有 updatedResources.userMysekaiHarvestMaps
    返回 {}    -> 有该结构，但四样稀有素材一个都没有
    返回 {id: {"count": n, "sites": {siteId: n}}} -> 命中
    """
    if not isinstance(obj, dict):
        return None
    resources = obj.get("updatedResources")
    if not isinstance(resources, dict):
        return None
    maps = resources.get("userMysekaiHarvestMaps")
    if not isinstance(maps, list):
        return None

    found: dict[int, HitRecord] = {}
    for entry in maps:
        site_id, drops = _split_harvest_map(entry)
        for drop in drops:
            rtype, rid, qty = _split_drop(drop)
            if rtype != "mysekai_material":
                continue
            try:
                rid = int(rid)
            except (TypeError, ValueError):
                continue
            if rid not in RARE_MATERIALS:
                continue
            n = int(qty) if isinstance(qty, (int, float)) and qty > 0 else 1
            rec = found.setdefault(rid, {"count": 0, "sites": {}})
            rec["count"] += n
            rec["sites"][site_id] = rec["sites"].get(site_id, 0) + n
    return found


def register_hit(found: dict[int, HitRecord], flow: http.HTTPFlow) -> str:
    """登记一次命中，返回编号（同时用作 flow 的标记）。"""
    global _hit_seq
    _hit_seq += 1
    hit_id = str(_hit_seq)

    items: list[MaterialItem] = []
    for rid, (name, icon) in RARE_MATERIALS.items():
        rec = found.get(rid)
        if not rec:
            continue
        where = "、".join(
            f"{SITE_NAMES.get(sid, f'场景{sid}')}×{n}" for sid, n in sorted(rec["sites"].items())
        )
        items.append(
            {
                "name": name,
                "icon": f"/local/icon/{icon}",
                "count": rec["count"],
                "where": where,
            }
        )

    HITS[hit_id] = {
        "path": flow.request.path,
        "time": time.strftime("%H:%M:%S"),
        "items": items,
    }
    # 只保留最近的若干条，避免长时间抓包把内存堆起来
    while len(HITS) > 500:
        HITS.pop(next(iter(HITS)), None)
    return hit_id


def _decrypt_aes_cbc(data: bytes, secrets: DecryptSecrets) -> bytes:
    return unpad(
        AES.new(secrets.key, AES.MODE_CBC, secrets.iv).decrypt(data), AES.block_size
    )


def decode_payload(data: bytes, secrets: DecryptSecrets) -> dict[str, Any]:
    plain = _decrypt_aes_cbc(data, secrets)
    return cast(dict[str, Any], msgpack.unpackb(plain, raw=False))


def _json_default(o: Any) -> str:
    """msgpack 解出的 bytes 等类型转成可 JSON 序列化的形式。"""
    if isinstance(o, (bytes, bytearray)):
        try:
            return o.decode("utf-8")
        except UnicodeDecodeError:
            return o.hex()
    return str(o)


def to_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, ensure_ascii=False, indent=2, default=_json_default
    ).encode("utf-8")


class ResponseDecrypt:
    """生成解密副本注入 UI；原 flow 不动，避免影响客户端与服务器之间的字节。"""

    def __init__(self, secrets: DecryptSecrets, rules: HostRules) -> None:
        self.secrets = secrets
        self.rules = rules

    def should_handle(self, flow: http.HTTPFlow) -> bool:
        return self.rules.should_decrypt(flow.request.pretty_host)

    def _decode(self, message: http.Message | None) -> Any:
        """把 AES+msgpack 的 body 解成 Python 对象；不是该格式就返回 None。"""
        if message is None:
            return None
        try:
            body = message.get_content(strict=False)
        except Exception:
            return None
        if not body:
            return None
        try:
            return decode_payload(body, self.secrets)
        except Exception:
            return None

    def decrypt_flow(self, flow: http.HTTPFlow) -> http.HTTPFlow | None:
        if not self.should_handle(flow):
            return None

        req_obj = self._decode(flow.request)
        resp_obj = self._decode(flow.response) if flow.response is not None else None
        if req_obj is None and resp_obj is None:
            return None

        dup = cast("http.HTTPFlow", flow.copy())
        if req_obj is not None:
            dup.request.set_content(to_json_bytes(req_obj))
            dup.request.headers["content-type"] = "application/json; charset=utf-8"
            dup.request.headers["x-decrypted-req"] = "1"
        if resp_obj is not None and dup.response is not None:
            dup.response.set_content(to_json_bytes(resp_obj))
            dup.response.headers["content-type"] = "application/json; charset=utf-8"
            dup.response.headers["x-decrypted"] = "1"

        dup.comment = ("[decrypted] " + (flow.comment or "")).strip()

        # 响应里带 harvest map 就顺手看一眼有没有稀有素材
        found = scan_harvest_maps(resp_obj) if resp_obj is not None else None
        if found:
            dup.marked = "🔴" + register_hit(found, flow)
        else:
            # mitmweb 会在列表的 Path 列渲染这个标记，用来和原始密文包区分
            dup.marked = MARKER
        return dup

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            from mitmproxy import ctx
        except Exception:
            return
        dup = self.decrypt_flow(flow)
        if dup is None:
            return
        try:
            ctx.master.addons.get("view").add([dup])
        except Exception as e:  # pragma: no cover
            logger.warning(f"解密副本注入失败: {e}")
            return

        hit_id = dup.marked[1:] if dup.marked.startswith("🔴") else ""
        if hit_id in HITS:
            names = "、".join(f"{i['name']}×{i['count']}" for i in HITS[hit_id]["items"])
            logger.info(f"稀有素材：{names}（{HITS[hit_id]['path']}）")


class TunnelRecorder:
    """把隧道连接的记录压到最小：留 host:port，不留内容，不在 capture 里的直接丢掉。

    mitmproxy 的 show_ignored_hosts 一开就是全局的——所有被放行的连接都会记一条，
    但 capture 名单可能只想留其中一部分，所以这里在 flow 建立时按名单裁剪。
    另外 mitmproxy 默认把整条流的所有字节都缓存进 flow.messages（官方文档也提醒了
    这会显著吃内存），抓半小时能堆到几百 MB，所以除第一条（TLS ClientHello）外
    收到就丢——列表里照样能看到连接和去向。
    """

    def __init__(self, rules: HostRules) -> None:
        self.rules = rules

    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        address = flow.server_conn.address
        host = address[0] if address else ""
        if self.rules.should_record(host):
            return
        try:
            from mitmproxy import ctx

            ctx.master.commands.call("view.flows.remove", [flow])
        except Exception as e:  # pragma: no cover
            logger.debug(f"过滤隧道记录失败: {e}")

    def tcp_message(self, flow: tcp.TCPFlow) -> None:
        if len(flow.messages) > 1:
            del flow.messages[1:]


# --------------------------------------------------------------------------
# mitmweb 前端注入（把素材图片画到红圈左边）
# --------------------------------------------------------------------------

# 往 mitmweb 的 index.html 里塞的两行
_INJECT = (
    '<link rel="stylesheet" href="/local/hits.css">\n'
    '        <script src="/local/hits.js" defer></script>\n        '
)


def _index_html(webapp: ModuleType) -> str:
    """读 mitmweb 自带的 index.html，注入 hits.js / hits.css。

    每次请求都读盘：mitmproxy 升级后静态文件名会变，这样不用跟着改。
    """
    # 打包成 zip/frozen 时 __file__ 可能缺失，直接抛 OSError 比 TypeError 好定位
    base = getattr(webapp, "__file__", None)
    if not base:
        raise OSError("mitmweb 的 app 模块没有 __file__，定位不到 index.html")
    path = os.path.join(os.path.dirname(base), "index.html")
    with open(path, encoding="utf-8") as f:
        html = f.read()
    if "/local/hits.js" in html:
        return html
    return html.replace("</head>", _INJECT + "</head>", 1)


def install_webui() -> bool:
    """给 mitmweb 挂上 /local/* 路由，并让首页注入素材脚本。

    为什么要绕这一圈：flow.marked 在 mitmweb 里只会被渲染成一段纯文本
    （<span class="marker">🔴1</span>），后端没法往里塞 <img>。
    所以分两步走 —— 后端登记「命中编号 + 素材清单」，前端 hits.js 看到红圈就去
    补图标。没装脚本时页面照常，只是看不到图片。

    必须在 WebMaster(opts) 构造之前调用：Application 在构造时就把 handlers 抄走了。
    """
    global _webui_installed
    if _webui_installed:
        return True
    try:
        import tornado.web
        from mitmproxy.tools.web import app as webapp

        class LocalIndex(webapp.IndexHandler):
            def get(self) -> None:
                try:
                    html = _index_html(webapp)
                except OSError as e:
                    self.set_status(500)
                    self.finish(f"读取 mitmweb index.html 失败: {e}")
                    return
                self.set_header("Content-Type", "text/html; charset=utf-8")
                self.set_header("Cache-Control", "no-store")
                self.write(html)

            post = get  # 登录表单走的也是这个 handler

        class LocalHits(webapp.RequestHandler):
            def get(self) -> None:
                self.set_header("Content-Type", "application/json; charset=utf-8")
                self.set_header("Cache-Control", "no-store")
                self.write(json.dumps(HITS, ensure_ascii=False))

        for i, handler in enumerate(webapp.handlers):
            if handler[0] == r"/":
                webapp.handlers[i] = (r"/", LocalIndex)
        # 顺序有意义：hits.json 必须排在通配的静态目录前面
        webapp.handlers.append((r"/local/hits\.json", LocalHits))
        # 三元素形式（附带 init kwargs）tornado 支持，只是 mitmproxy 的标注只写了二元组
        static_route: Any = (r"/local/(.*)", tornado.web.StaticFileHandler, {"path": WEBUI_DIR})
        webapp.handlers.append(static_route)

        # mitmweb 的接口会把任何非空 marked 归一化成一个 🔴
        # （flow_to_json 里是 emoji.get(flow.marked, "🔴")），编号会被吃掉，
        # 前端就没法知道这行是第几次命中。这里只放行 "🔴<编号>"，其余行为不变。
        original = getattr(webapp, "flow_to_json", None)
        if callable(original) and not getattr(webapp, "_mysk_flow_to_json", False):

            def flow_to_json(flow: http.HTTPFlow, *args: Any, **kwargs: Any) -> dict[str, Any]:
                data = cast(dict[str, Any], original(flow, *args, **kwargs))
                marked = getattr(flow, "marked", "")
                if isinstance(marked, str) and marked.startswith("🔴"):
                    data["marked"] = marked
                return data

            # 故意放宽签名（原函数只接受 Flow），故与下游标注对不上
            webapp.flow_to_json = flow_to_json  # type: ignore[assignment]
            setattr(webapp, "_mysk_flow_to_json", True)
    except Exception as e:  # pragma: no cover - 版本变化时不影响抓包
        print(f"      WebUI 注入: 失败（{e}），红圈照旧、图标不可用")
        return False

    _webui_installed = True
    return True


# --------------------------------------------------------------------------
# adb 辅助
# --------------------------------------------------------------------------

# adb 偶尔会卡住（设备忙、无线断开、adbd 无响应），给每条命令兜个超时，
# 免得上一步卡死把 Ctrl+C 后的清理也一起拖住。
ADB_TIMEOUT: float = 20.0


def _run(cmd: list[str], timeout: float = ADB_TIMEOUT) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"      [警告] adb 命令 {timeout:.0f}s 未返回：{' '.join(cmd[3:])}")
        print("             多半是 adb server 卡住了（设备断线/换网后常见）：adb kill-server")
        # 调用方只看 returncode，用 124（timeout 的惯例）表示失败
        return subprocess.CompletedProcess(cmd, 124, "", "timeout")


def _die(msg: str) -> NoReturn:
    print(f"\n[错误] {msg}\n", file=sys.stderr)
    sys.exit(1)


def list_devices(adb: str) -> None:
    """列出 adb 认到的设备，并给出每个设备能直接用的 target 写法。

    USB 设备的序列号就是 `adb devices` 第一列（设备自己的 ro.serialno）；
    网络设备的"序列号"是 ip:端口，本身就已经是完整 target。
    """
    r = _run([adb, "devices", "-l"])
    if r.returncode != 0:
        _die(f"adb devices 执行失败：{r.stderr.strip() or '超时，试试 adb kill-server'}")

    rows: list[tuple[str, str, str]] = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[1] not in ("device", "unauthorized", "offline"):
            continue
        model = next((x[len("model:"):] for x in parts[2:] if x.startswith("model:")), "")
        rows.append((parts[0], parts[1], model))

    if not rows:
        print("\n没有设备在线。")
        print("  USB    ：检查数据线（要能传数据）、平板上「允许 USB 调试」是否点过")
        print("  无线   ：先 adb connect <ip>:<端口>，或看平板开发者选项里的「无线调试」")
        return

    print("\nadb 认到的设备：")
    for serial, state, model in rows:
        print(f"  {serial:<22} {state:<14} {model}")
        if state != "device":
            print("    （状态不是 device，先处理授权/掉线，再谈抓包）")
            continue
        if ":" in serial:
            print(f"    -> uv run main.py {serial}")
        else:
            print(f"    -> uv run main.py {serial} --emudhra      # 抓平板本身")
            print(f"    -> uv run main.py {serial}:6556           # 抓平板里的虚拟机")
    print()


_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass(frozen=True)
class Target:
    """这次要操作的设备（由命令行 target 解析而来）。"""

    serial: str
    """后续所有 adb -s 用的标识：USB 序列号，或 127.0.0.1:<端口>。"""

    connect: str | None = None
    """需要先 adb connect 的地址；None 表示 USB 直连，不用 connect。"""

    forward: tuple[str, int] | None = None
    """(宿主序列号, 端口)：先经 USB 把宿主上的这个端口转发到本机回环，再去 connect。"""


def resolve_target(raw: str) -> Target:
    """把命令行里的 target 解析成要操作的设备。

        10.1.162.244:6556   -> 直接 connect（虚拟机走局域网）
        192.168.1.23:37015  -> 直接 connect（平板无线调试）
        R58M1234AB          -> USB 直连宿主本身，adb 里已在线，不用 connect
        R58M1234AB:6556     -> 经 USB 转发到宿主的 6556，再 connect 本机回环上的同一个端口

    最后一种就是「USB 有线连物理机里的虚拟机」：USB 只能到平板，VM 的 adbd
    挂平板的 6556，所以借 USB 通道把端口搬到 PC 本机，再按普通网络设备连。
    判断依据是冒号前是不是 IPv4——是就按网络设备，不是就当 USB 序列号。

    端口不给默认值：只写 IP 会直接报错，避免连到不该连的端口上去。
    """
    target = raw.strip()
    if not target:
        _die("target 不能为空")

    if ":" not in target:
        if _IPV4_RE.match(target):
            _die(f"{target} 少了端口，写成 {target}:<端口>（虚拟机 6556，无线调试看开发者选项里的端口）")
        return Target(serial=target)

    host, _, port_text = target.rpartition(":")
    if not port_text.isdigit() or not 0 < int(port_text) < 65536:
        _die(f"{target} 的端口不对，写成 <ip>:<端口> 或 <USB 序列号>:<端口>")
    port = int(port_text)

    if _IPV4_RE.match(host) or host.lower() == "localhost":
        return Target(serial=target, connect=target)
    if not host:
        _die(f"{target} 少了主机名或序列号，写成 <ip>:<端口> 或 <USB 序列号>:<端口>")

    # 冒号前不是 IP -> 当成 USB 序列号，走「USB 转发 + 回环 connect」的套娃链路
    loop = f"127.0.0.1:{port}"
    return Target(serial=loop, connect=loop, forward=(host, port))


def _device_state(adb: str, serial: str) -> str | None:
    out = _run([adb, "devices"]).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == serial:
            return parts[1]
    return None


def _local_key_fingerprint() -> str | None:
    """本机 adb 公钥的 MD5 指纹，格式与虚拟机弹窗里显示的一致。"""
    path = os.path.join(os.path.expanduser("~"), ".android", "adbkey.pub")
    try:
        with open(path, encoding="utf-8") as f:
            blob = base64.b64decode(f.read().split()[0])
        return ":".join(f"{b:02X}" for b in hashlib.md5(blob).digest())
    except Exception:
        return None


def _forward_exists(adb: str, host: str, port: int) -> bool:
    """这条映射是否已经在 adb 里（`forward --list` 每行：<serial> tcp:<本地> tcp:<远端>）。"""
    out = _run([adb, "-s", host, "forward", "--list"]).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == host:
            if parts[1] == f"tcp:{port}" and parts[2] == f"tcp:{port}":
                return True
    return False


def _setup_usb_forward(adb: str, host: str, port: int) -> None:
    """把宿主机（物理平板）上的 port 经 USB 搬到本机回环，供后面 adb connect 用。

    纯 USB 抓虚拟机的关键一步：USB 只能到平板，VM 的 adbd 挂在平板的这个端口上，
    所以要借平板的 adb 通道把端口搬到 PC，再当成普通网络设备连 127.0.0.1:<port>。
    """
    state = _device_state(adb, host)
    if state != "device":
        _die(
            f"USB 宿主 {host} 不可用（状态：{state or '不在 adb devices 里'}）。\n"
            "       1) 数据线插好，并在平板弹出的「USB 用途」里选「传输文件」而不是「仅充电」\n"
            "       2) 平板端弹窗点「允许 USB 调试」（指纹对不上说明批了别的机器）\n"
            "       3) 换根线（不少线只有电源针，没有数据针）"
        )

    # 映射已在就直接复用：删了重建会连带掐断已经连上的 transport，
    # 而虚拟机每建一条新 transport 都要在画面里重新点一次「确定」。
    if _forward_exists(adb, host, port):
        print(f"      USB 转发 tcp:{port} 已存在，复用（{host} → 本机 127.0.0.1:{port}）")
        return

    print(f"      USB 转发 tcp:{port}：{host} → 本机 127.0.0.1:{port}")
    # 同端口已映射到别处时 add 会失败，先删一次（没有这条映射也无害）
    _run([adb, "-s", host, "forward", "--remove", f"tcp:{port}"])
    r = _run([adb, "-s", host, "forward", f"tcp:{port}", f"tcp:{port}"])
    if r.returncode != 0:
        _die(
            f"USB 转发建立失败：{r.stderr.strip() or r.stdout.strip()}\n"
            f"       多半是本机 {port} 端口被占用，先关掉占着它的程序再来"
        )


def ensure_device(
    adb: str,
    target: Target,
    timeout: int = 25,
    auth_timeout: int = 180,
) -> None:
    if target.forward is not None:
        _setup_usb_forward(adb, *target.forward)

    print(f"[1/4] 连接 {target.serial} ...")
    if target.connect is not None:
        _run([adb, "connect", target.connect])

    start = time.time()
    warned = False
    last_tip = 0.0
    while True:
        state = _device_state(adb, target.serial)
        if state == "device":
            print("      已连接")
            return

        if state == "unauthorized":
            if not warned:
                print(f"      等待授权：请在设备上点「允许 USB 调试」的「确定」（最多等 {auth_timeout} 秒）...")
                fp = _local_key_fingerprint()
                if fp:
                    print(f"      本机公钥指纹：{fp}")
                    print("      弹窗里的指纹要和上面一致；对不上说明批的是别台机器的 key")
                print("      没有弹窗？USB 的话拔插一次数据线；虚拟机里把「ADB 调试」关掉再打开（等于重启 adbd）")
                warned = True
                last_tip = time.time()
            elif time.time() - last_tip >= 30:
                print(f"      仍在等待授权（已等 {int(time.time() - start)} 秒）...")
                last_tip = time.time()

        limit = auth_timeout if warned else timeout
        if time.time() - start > limit:
            if state == "unauthorized":
                _die(
                    "授权超时：设备连得上（状态 unauthorized），只是这台 PC 的 key 没被批准。\n"
                    "       1) 虚拟机里「ADB 调试」开关 关→开，再重跑（adbd 重启才会重读 adb_keys）\n"
                    "       2) 把设备切到前台、点亮屏幕、回桌面，再重跑（弹窗要 SystemUI 在前台）\n"
                    "       3) USB 物理平板拔插一次数据线，或在开发者选项里「撤销 USB 调试授权」再来\n"
                    "       4) 别连着反复 connect：每次都会新建 transport，弹窗只会越堆越多\n"
                    f"       本机公钥指纹：{_local_key_fingerprint() or '读取失败'}"
                )
            if target.forward is not None:
                host, port = target.forward
                _die(
                    f"连不上 {target.serial}（USB 转发模式）。请确认：\n"
                    f"       1) 宿主 {host} 还在线（adb devices 里状态要是 device）\n"
                    f"       2) 转发还在（adb -s {host} forward --list 应能看到 tcp:{port}）\n"
                    "       3) 虚拟机里「ADB 调试」开关是否打开（关→开等于重启 adbd）\n"
                    f"       4) 手工试一下：adb -s {host} forward tcp:{port} tcp:{port} && "
                    f"adb connect {target.serial}"
                )
            _die(
                f"连不上 {target.serial}。请确认：\n"
                "       1) 设备是否在线（USB 线插好 / 无线调试是否还连着），虚拟机里的 ADB 开关是否打开\n"
                "       2) IP 和端口是否正确（无线调试的端口每次开都会变，看「无线调试」页面上的 IP:端口）\n"
                f"       3) 手工试一下：adb connect {target.serial}"
            )
        time.sleep(1)


def set_proxy(adb: str, serial: str, value: str) -> subprocess.CompletedProcess[str]:
    return _run([adb, "-s", serial, "shell", f"settings put global http_proxy {value}"])


def cleanup(adb: str, serial: str, proxy_port: int) -> None:
    """还原代理与隧道。

    两步都是独立的 `adb` 调用：设备上 `settings` 其实是个 Java 程序，每次都要冷启动一个
    app_process，再加上无线 adb 的往返、设备当时可能还在跑游戏，所以不会"瞬间"完成。
    这里逐步打印耗时，卡在哪一步一眼能看出来。
    """
    print("\n[清理] 还原代理与隧道 ...")
    total = time.perf_counter()

    t = time.perf_counter()
    r = set_proxy(adb, serial, ":0")
    print(f"      清除全局代理  {time.perf_counter() - t:.1f}s")
    if r.returncode != 0:
        # 这一步失败最讨厌：代理留着，设备上所有 App 都会"断网"
        print("      [警告] 代理可能没清掉！手动执行一次：")
        print(f'             adb -s {serial} shell "settings put global http_proxy :0"')

    t = time.perf_counter()
    _run([adb, "-s", serial, "reverse", "--remove", f"tcp:{proxy_port}"])
    print(f"      撤销反向隧道  {time.perf_counter() - t:.1f}s")

    print(f"      完成，设备已恢复直连（共 {time.perf_counter() - total:.1f}s）")


# --------------------------------------------------------------------------
# mitmweb
# --------------------------------------------------------------------------

async def _serve(
    opts: options.Options,
    web_port: int,
    token: str,
    secrets: DecryptSecrets | None,
    rules: HostRules,
    emudhra: str | None,
) -> None:
    from mitmproxy.tools.web.master import WebMaster

    # secrets 为 None 表示不启用解密（没配密钥或显式 --no-decrypt）
    if secrets is not None:
        install_webui()

    # web_* 选项由 WebAuth addon 注册，必须在 WebMaster 构造之后再赋值
    master = WebMaster(opts)
    master.options.web_host = "127.0.0.1"
    master.options.web_port = web_port
    master.options.web_password = token
    master.options.web_open_browser = False

    if emudhra:
        # 这个选项也是 tlsconfig addon 注册的，同样得等 master 构造好
        if not hasattr(master.options, emudhra):
            raise RuntimeError(
                f"当前 mitmproxy 没有 {emudhra} 选项（需要 12.3+），请先升级依赖"
            )
        # 赋值会立刻触发 tlsconfig.configure()，把 certstore 的签发 CA 换成泄露的中间 CA
        setattr(master.options, emudhra, True)
        print(f"      证书: {emudhra} 模式（设备端无需安装证书）")

    if rules.capture:
        master.addons.add(TunnelRecorder(rules))
        print("      隧道记录: 已启用（未探针的连接只留 host:port）")

    if secrets is not None:
        try:
            master.addons.add(ResponseDecrypt(secrets, rules))
            print("      响应解密: 已启用（" + "、".join(rules.decrypt) + "）")
            print("      稀有素材: " + "、".join(n for n, _ in RARE_MATERIALS.values()))
        except Exception as e:
            print(f"      响应解密: 加载失败 -> {e}")

    loop = asyncio.get_running_loop()

    def _stop(*_: Any) -> None:
        loop.call_soon_threadsafe(master.shutdown)

    try:
        loop.add_signal_handler(signal.SIGINT, _stop)
        loop.add_signal_handler(signal.SIGTERM, _stop)
    except (NotImplementedError, RuntimeError):
        # Windows 的 ProactorEventLoop 走这里
        signal.signal(signal.SIGINT, lambda *a: _stop())
        signal.signal(signal.SIGTERM, lambda *a: _stop())

    await master.run()


def start_ui(
    proxy_port: int,
    web_port: int,
    token: str,
    upstream: str | None,
    secrets: DecryptSecrets | None,
    rules: HostRules,
    emudhra: str | None,
) -> None:
    from mitmproxy import options

    opts_kwargs: dict[str, Any] = {}
    if upstream:
        # mode 是核心选项，必须在构造时就给定，事后再赋不会生效
        opts_kwargs["mode"] = [f"upstream:{upstream}"]
    # allow_hosts 决定谁换证书，ignore_hosts 决定谁连隧道都别进（两层 ignore 合成一个集合，
    # 事后再按 capture 名单把不该留的删掉），show_ignored_hosts 让隧道连接也留一条记录。
    opts_kwargs["allow_hosts"] = rules.allow_patterns()
    ignore = rules.ignore_patterns()
    if ignore:
        opts_kwargs["ignore_hosts"] = ignore
    opts_kwargs["show_ignored_hosts"] = bool(rules.capture)
    opts = options.Options(
        listen_host="127.0.0.1", listen_port=proxy_port, **opts_kwargs
    )

    print()
    print("=" * 66)
    print(f"  Web UI : http://127.0.0.1:{web_port}/?token={token}")
    print(f"  代理   : 127.0.0.1:{proxy_port}（设备侧经 adb reverse 接入）")
    print(f"  上游   : {upstream or '直连'}")
    if emudhra:
        print(f"  证书   : {emudhra}（设备端无需安装证书）")
    else:
        print("  证书   : mitmproxy 自带 CA（设备侧必须已信任，虚拟机里才做得到）")
    print(f"  记录   : {_describe(rules.capture, rules.capture_ignore)}")
    print(f"  探针   : {_describe(rules.probe, rules.probe_ignore)}")
    if secrets is not None:
        print(f"  解密   : {_describe(rules.decrypt, rules.decrypt_ignore)}")
    else:
        print("  解密   : 关闭（没配密钥）")
    if secrets is not None:
        print(f"  素材   : {'、'.join(n for n, _ in RARE_MATERIALS.values())}（命中行：红圈左边显示图标）")
    print("  Ctrl+C 结束并自动清理")
    print("=" * 66)
    print()

    asyncio.run(_serve(opts, web_port, token, secrets, rules, emudhra))


# --------------------------------------------------------------------------

def main() -> None:
    # 让日志即时显示（即使被重定向到文件/管道）
    for stream in (sys.stdout, sys.stderr):
        try:
            cast(Any, stream).reconfigure(line_buffering=True)
        except Exception:
            pass

    # .env 必须在读任何环境变量之前加载；已存在的真实环境变量优先，不会被覆盖
    load_env()

    p = argparse.ArgumentParser(
        description="抓取虚拟机 / 物理平板的流量（adb reverse + mitmweb）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "例子:\n"
            "  uv run main.py 10.1.162.244:6556          # 虚拟机（局域网）\n"
            "  uv run main.py 192.168.1.23:37015         # 平板无线调试\n"
            "  uv run main.py R58M1234AB --emudhra       # 平板 USB，免装证书\n"
            "  uv run main.py R58M1234AB:6556            # 虚拟机，走平板 USB 转发（不依赖网络）\n"
            "  uv run main.py 10.1.162.244:6556 --web-port 9000\n"
            "  uv run main.py 10.1.162.244:6556 --upstream http://127.0.0.1:7897\n"
        ),
    )
    p.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="列出 adb 认到的设备（序列号 / 状态 / 型号）及可直接用的 target 写法，然后退出",
    )
    p.add_argument(
        "target",
        nargs="?",
        help=(
            "设备地址：<ip>:<端口>（局域网）| USB 序列号（adb devices 里那一列，直连物理机本身）"
            " | <序列号>:<端口>（经这台 USB 设备转发该端口，用于物理机里的虚拟机）"
        ),
    )
    cert = p.add_mutually_exclusive_group()
    cert.add_argument(
        "--emudhra",
        action="store_true",
        help="用泄露的 eMudhra 中间 CA 现签证书，设备无需安装证书（物理平板没 root 时用这个）",
    )
    cert.add_argument(
        "--emudhra-old",
        action="store_true",
        help="同上，但优先用 Sectigo AAA 交叉签名那条链（老的信任库才需要）",
    )
    p.add_argument("--proxy-port", type=int, default=8080, help="本机代理端口（默认 8080）")
    p.add_argument("--web-port", type=int, default=8081, help="Web UI 端口（默认 8081）")
    p.add_argument("--token", default=None, help="Web UI 访问 token（默认随机生成）")
    p.add_argument(
        "--upstream",
        default="auto",
        help="上游代理：auto=读 $http_proxy（默认）| none=直连 | http://127.0.0.1:7897",
    )
    p.add_argument("--adb", default=None, help="adb 可执行文件路径（默认从 PATH 找）")
    p.add_argument(
        "--no-decrypt",
        action="store_true",
        help="关闭请求/响应解密副本",
    )
    args = p.parse_args()

    adb = args.adb or shutil.which("adb")
    if not adb:
        _die("找不到 adb，请把 platform-tools 加进 PATH，或用 --adb 指定路径")

    if args.list:
        list_devices(adb)
        return
    if not args.target:
        _die("没给 target。先跑 uv run main.py --list 看有哪些设备，按提示里的写法填")

    target = resolve_target(args.target)
    emudhra = "emudhra_old" if args.emudhra_old else ("emudhra" if args.emudhra else None)
    if target.connect is None and not emudhra:
        print("[提示] USB 直连的是物理机本身，装不了系统证书；游戏报网络错误就加 --emudhra")
    token = args.token or token_hex(8)

    rules = load_host_rules()
    secrets = None if args.no_decrypt else load_secrets()

    if args.upstream == "auto":
        upstream = os.environ.get("http_proxy") or os.environ.get("HTTPS_PROXY") or None
        if upstream and not upstream.startswith("http"):
            upstream = None
    elif args.upstream.lower() == "none":
        upstream = None
    else:
        upstream = args.upstream

    ensure_device(adb, target)

    print(f"[2/4] 建立反向隧道 tcp:{args.proxy_port} ...")
    r = _run([adb, "-s", target.serial, "reverse", f"tcp:{args.proxy_port}", f"tcp:{args.proxy_port}"])
    if r.returncode != 0:
        _die(f"reverse 建立失败：{r.stderr.strip()}")

    print(f"[3/4] 设置设备全局代理 127.0.0.1:{args.proxy_port} ...")
    r = set_proxy(adb, target.serial, f"127.0.0.1:{args.proxy_port}")
    if r.returncode != 0:
        _die(f"设置代理失败：{r.stderr.strip() or r.stdout.strip() or '见上面的警告'}")

    print("[4/4] 启动 mitmweb")
    try:
        start_ui(
            args.proxy_port,
            args.web_port,
            token,
            upstream,
            secrets,
            rules,
            emudhra,
        )
    except (OSError, RuntimeError) as e:
        _die(f"启动失败：{e}")
    except KeyboardInterrupt:
        pass
    finally:
        cleanup(adb, target.serial, args.proxy_port)


if __name__ == "__main__":
    main()

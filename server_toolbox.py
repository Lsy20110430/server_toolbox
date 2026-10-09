# =============================================================================
#  服务器检测工具箱  Server Check Toolbox  v1.0
#
#  【运行环境】
#      Python 3.8+（Windows / Linux / macOS 均可）
#      运行方式：python server_toolbox.py
#
#  【前置包 / 依赖说明】
#      第三方 Python 包：无，无需 pip install。
#      本程序只用 Python 标准库：
#          socket, ssl, subprocess, ipaddress, errno, platform,
#          re, os, sys, time, concurrent.futures
#      可选的外部命令（仅 ICMP 存活探测会用到，缺失会自动降级为 TCP 探测）：
#          Debian / Ubuntu : sudo apt install iputils-ping
#          CentOS / RHEL   : sudo yum install iputils
#          Alpine Linux    : sudo apk add iputils
#          macOS / Windows : 系统自带，无需安装
#
#  【隐私与安全约定】
#      1) 所有探测都在“本机”和“目标服务器”之间直接完成，不经过任何第三方
#         服务、公共 API、代理或中继，绝不把 IP 交给外部。
#      2) 四项检测功能（存活 / 双向 / 端口 / 防护）只接受 IP 字面量、不做域名解析，
#         因此不会向 DNS 泄露目标。功能 5「服务器IP解析」例外：它需要把你要解析的
#         域名提交给本机配置的 DNS 服务器，这是 DNS 查询本身的必要行为；同时它的
#         解析结果会明文显示（否则该功能没有意义）。
#      3) 输出默认对 IP 脱敏（例如 203.0.113.7 -> 203.*.*.*），
#         程序不写日志文件、不把 IP 落盘。
#         若只是在本机屏幕上看明文，可在运行前设置环境变量（仅影响显示）：
#             Linux / macOS :  export TOOLBOX_UNMASK=1
#             Windows CMD    :  set TOOLBOX_UNMASK=1
#      4) 本程序只做常规的 TCP 连接测试、ICMP 回声探测与 HTTP 响应头分析，
#         不发送攻击载荷、不做漏洞利用、不猜测口令、不修改目标任何状态。
#      5) 请仅对你本人拥有或已获得书面授权的服务器使用本工具。
# =============================================================================

import errno
import getpass
import ipaddress
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
import warnings
from concurrent.futures import ThreadPoolExecutor

APP_NAME = "服务器检测工具箱"
APP_VER = "1.0"

# 显示脱敏开关：仅控制本机屏幕显示，不改变任何网络行为
UNMASK = str(os.environ.get("TOOLBOX_UNMASK", "")).strip().lower() not in (
    "", "0", "false", "no",
)
USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

DEFAULT_UA = "ServerCheckToolbox/1.0"
MAX_PORTS_PER_RUN = 64          # 单次最多探测的端口数，避免变成大范围扫描器
TCP_TIMEOUT = 2.0

# 存活兜底探测用的高辨识度端口
ALIVE_PROBE_PORTS = [80, 443, 22, 3389, 8080]

COMMON_PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"), (53, "DNS"),
    (80, "HTTP"), (110, "POP3"), (135, "RPC"), (139, "NetBIOS"), (143, "IMAP"),
    (443, "HTTPS"), (445, "SMB"), (993, "IMAPS"), (995, "POP3S"),
    (1433, "MSSQL"), (1521, "Oracle"), (3306, "MySQL"), (3389, "RDP"),
    (5432, "PostgreSQL"), (5900, "VNC"), (6379, "Redis"),
    (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"), (27017, "MongoDB"),
]
PORT_NAMES = dict(COMMON_PORTS)

# 对外开放时需要留意的管理 / 数据库类端口
SENSITIVE_PORTS = {23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017}

# 用于判断“是否对任意端口静默丢包”的几个高编号端口
DROP_TEST_PORTS = [45678, 49123, 53117]

# 常见防护设备 / CDN 在响应头里留下的特征
WAF_SIGNATURES = [
    (b"cloudflare", "Cloudflare"),
    (b"cf-ray", "Cloudflare"),
    (b"cf-cache-status", "Cloudflare"),
    (b"x-amz-cf-id", "AWS CloudFront"),
    (b"awselb", "AWS ELB"),
    (b"x-sucuri-id", "Sucuri WAF"),
    (b"x-akamai", "Akamai"),
    (b"akamaighost", "Akamai"),
    (b"incap_ses", "Imperva / Incapsula"),
    (b"visid_incap", "Imperva / Incapsula"),
    (b"x-iinfo", "Imperva / Incapsula"),
    (b"bigipserver", "F5 BIG-IP"),
    (b"mod_security", "ModSecurity"),
    (b"x-protected-by", "通用 WAF"),
    (b"x-waf", "通用 WAF"),
    (b"x-denied-reason", "通用 WAF"),
]

STATE_TEXT = {
    "open": "开放",
    "closed": "关闭（有响应 / RST）",
    "filtered": "无响应（被过滤）",
    "unreachable": "网络不可达",
    "error": "探测出错",
}

MENU = """  --------------------------------------------------------
    [1] 服务器存活检测
    [2] 服务器双向检测
    [3] 服务器端口检测
    [4] 服务器防护检测
    [5] 服务器IP解析
    [6] 退出程序
  --------------------------------------------------------"""


# --------------------------------------------------------------------------
# 输出小工具
# --------------------------------------------------------------------------
def _paint(text, code):
    if not USE_COLOR:
        return text
    return "\033[%sm%s\033[0m" % (code, text)


def green(t):
    return _paint(t, "32")


def yellow(t):
    return _paint(t, "33")


def red(t):
    return _paint(t, "31")


def cyan(t):
    return _paint(t, "36")


def bold(t):
    return _paint(t, "1")


def clear_screen():
    if not sys.stdout.isatty():
        return
    if os.name == "nt":
        os.system("cls")
    else:
        # 直接用转义序列，不依赖系统里的 clear 命令
        sys.stdout.write("\033[H\033[2J\033[3J")
        sys.stdout.flush()


def mask(ip):
    """对 IP 做显示脱敏，避免明文外露。"""
    text = str(ip)
    if UNMASK:
        return text
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return "***"
    if addr.version == 4:
        return addr.exploded.split(".")[0] + ".*.*.*"
    parts = addr.exploded.split(":")
    return parts[0] + ":" + parts[1] + "::*"


def fmt_rtt(ms):
    return "—" if ms is None else "%.1f ms" % ms


def header(index, title):
    print("\n" + "=" * 58)
    print("  [%d] %s" % (index, title))
    print("=" * 58)


def pause():
    try:
        input("\n  按回车键返回主菜单 ...")
    except (EOFError, KeyboardInterrupt):
        print()


# --------------------------------------------------------------------------
# 输入校验
# --------------------------------------------------------------------------
def read_hidden(prompt):
    """读取输入但不回显，避免 IP 明文留在屏幕上。"""
    if not sys.stdin.isatty():
        # 管道 / 重定向场景没有终端可隐藏，按普通输入处理
        return input(prompt)
    print(prompt, end="", flush=True)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return getpass.getpass("")


def ask_ip(prompt="请输入服务器 IP 地址: "):
    """只接受 IP 字面量，返回 ip_address 对象；输入 q 返回 None。"""
    while True:
        try:
            raw = read_hidden("  " + prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if not raw:
            print("  " + yellow("× 输入为空，请重新输入（输入 q 可返回主菜单）"))
            continue
        if raw.lower() in ("q", "quit", "exit", "back", "b", "0"):
            return None
        text = raw
        # 顺手支持 1.2.3.4:80 这种写法，端口在这里忽略
        if "." in text and text.count(":") == 1 and "::" not in text:
            text = text.rsplit(":", 1)[0]
        try:
            return ipaddress.ip_address(text)
        except ValueError:
            print("  " + yellow("× 只接受 IP 字面量（如 203.0.113.7 或 2001:db8::1），不支持域名"))
            continue


def ask_port(prompt, default):
    while True:
        try:
            raw = input("  %s [直接回车 = %d]: " % (prompt, default)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        if not raw:
            return default
        if raw.isdigit() and 1 <= int(raw) <= 65535:
            return int(raw)
        print("  " + yellow("× 端口需为 1-65535 之间的数字"))


def ask_domain(prompt="请输入要解析的域名: "):
    """域名输入（可见，方便核对拼写），返回小写域名；输入 q 返回 None。"""
    while True:
        try:
            raw = input("  " + prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if not raw:
            print("  " + yellow("× 输入为空，请重新输入（输入 q 可返回主菜单）"))
            continue
        if raw.lower() in ("q", "quit", "exit", "back", "b", "0"):
            return None
        domain = raw.rstrip(".").lower()
        if is_ip_literal(domain):
            print("  " + cyan("这已经是 IP 字面量了，无需解析") + "    可直接用于前四项检测")
            continue
        if not is_valid_domain(domain):
            print("  " + yellow("× 域名格式不正确，示例：example.com"))
            continue
        return domain


def is_ip_literal(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def is_valid_domain(domain):
    if len(domain) > 253 or "." not in domain:
        return False
    for label in domain.split("."):
        if not 1 <= len(label) <= 63:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return False
    return True


def parse_port_list(text, limit=MAX_PORTS_PER_RUN):
    """解析 22,80,8000-8010 这类端口表达式，返回去重排序后的列表。"""
    ports = []
    for piece in text.replace("，", ",").split(","):
        piece = piece.strip()
        if not piece:
            continue
        if "-" in piece:
            left, _, right = piece.partition("-")
            if not (left.strip().isdigit() and right.strip().isdigit()):
                raise ValueError("端口区间格式不正确：%s" % piece)
            start, end = int(left), int(right)
            if start > end:
                start, end = end, start
            ports.extend(range(start, end + 1))
        else:
            if not piece.isdigit():
                raise ValueError("端口格式不正确：%s" % piece)
            ports.append(int(piece))
    ports = [p for p in dict.fromkeys(ports) if 1 <= p <= 65535]
    if not ports:
        raise ValueError("没有解析到有效端口")
    if len(ports) > limit:
        raise ValueError("一次最多探测 %d 个端口（本次 %d 个），请缩小范围" % (limit, len(ports)))
    return sorted(ports)


# --------------------------------------------------------------------------
# 基础探测
# --------------------------------------------------------------------------
def make_socket(ip, timeout=None):
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    if timeout is not None:
        sock.settimeout(timeout)
    return sock


def connect_tcp(ip, port, timeout=3.0):
    sock = make_socket(ip, timeout)
    sock.connect((str(ip), port))
    return sock


def tcp_probe(ip, port, timeout=TCP_TIMEOUT):
    """TCP 连接探测，返回 {state, rtt}。"""
    sock = None
    start = time.perf_counter()
    try:
        sock = make_socket(ip, timeout)
        sock.connect((str(ip), port))
        return {"state": "open", "rtt": time.perf_counter() - start}
    except socket.timeout:
        return {"state": "filtered", "rtt": None}
    except ConnectionRefusedError:
        return {"state": "closed", "rtt": time.perf_counter() - start}
    except OSError as exc:
        if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EHOSTDOWN, errno.ENETDOWN):
            return {"state": "unreachable", "rtt": None}
        if exc.errno == errno.ECONNREFUSED:
            return {"state": "closed", "rtt": time.perf_counter() - start}
        return {"state": "error", "rtt": None}
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def scan_ports(ip, ports, timeout=TCP_TIMEOUT, workers=32):
    def probe(port):
        result = tcp_probe(ip, port, timeout)
        result["port"] = port
        return result

    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(ports)))) as pool:
        results = list(pool.map(probe, ports))
    return sorted(results, key=lambda r: r["port"])


def _ping_command(ip, timeout):
    system = platform.system().lower()
    wait_ms = int(timeout * 1000)
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(wait_ms)]
        if ip.version == 6:
            cmd.append("-6")
        return cmd + [str(ip)]
    if system == "darwin":
        if ip.version == 6:
            return ["ping6", "-c", "1", "-W", str(wait_ms), str(ip)]
        return ["ping", "-c", "1", "-W", str(wait_ms), str(ip)]
    cmd = ["ping"]
    if ip.version == 6:
        cmd.append("-6")
    return cmd + ["-c", "1", "-W", str(max(1, int(round(timeout)))), str(ip)]


def icmp_ping(ip, timeout=2.0):
    """ICMP 回声探测，返回 (ping 是否可用, 是否存活, RTT 毫秒)。"""
    cmd = _ping_command(ip, timeout)
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 3,
        )
    except FileNotFoundError:
        return False, False, None
    except subprocess.TimeoutExpired:
        return True, False, None
    except OSError:
        return False, False, None
    if proc.returncode != 0:
        return True, False, None
    found = re.search(rb"[Tt]ime[=<]\s*([0-9.]+)\s*ms", proc.stdout)
    return True, True, float(found.group(1)) if found else None


def http_probe_any(ip, port, timeout=5.0):
    """不确知协议时：先按明文，再按 TLS 各试一次。"""
    result = http_probe(ip, port, use_tls=False, timeout=timeout)
    if result is None:
        result = http_probe(ip, port, use_tls=True, timeout=timeout)
    return result


def http_probe(ip, port, use_tls=False, user_agent=DEFAULT_UA, timeout=5.0):
    """发一个 HEAD 请求并只读响应头（不传输任何数据），失败返回 None。"""
    sock = None
    try:
        sock = connect_tcp(ip, port, timeout)
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=None)
        host = str(ip) if ip.version == 4 else "[%s]" % ip
        ua_line = "" if user_agent is None else "User-Agent: %s\r\n" % user_agent
        request = (
            "HEAD / HTTP/1.0\r\nHost: %s\r\n%sConnection: close\r\n\r\n"
            % (host, ua_line)
        ).encode("ascii", "ignore")
        sock.sendall(request)

        data = b""
        deadline = time.time() + timeout
        while b"\r\n\r\n" not in data and time.time() < deadline:
            chunk = sock.recv(2048)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break

        head = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace")
        lines = head.split("\r\n")
        status = None
        matched = re.match(r"HTTP/\d\.\d\s+(\d{3})", lines[0] if lines else "")
        if matched:
            status = int(matched.group(1))
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, _, value = line.partition(":")
                headers.setdefault(key.strip().lower(), value.strip())
        return {"status": status, "headers": headers, "head": head,
                "port": port, "tls": use_tls}
    except (OSError, ssl.SSLError, ValueError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# --------------------------------------------------------------------------
# 功能 1：服务器存活检测
# --------------------------------------------------------------------------
def feature_alive():
    header(1, "服务器存活检测")
    ip = ask_ip()
    if ip is None:
        return
    print("\n  目标服务器 : %s" % bold(mask(ip)))
    print("  探测方式   : ICMP 回声往返 + 常用端口 TCP 探测（本机直连，不经第三方）")

    print("\n  (1/2) ICMP 回声探测 ...")
    available, alive, rtt = icmp_ping(ip, timeout=2.0)
    if not available:
        print("        " + yellow("跳过：本机没有可用的 ping 命令（可用 TCP 探测兜底）"))
    elif alive:
        print("        " + green("有响应") + "    往返延迟 %s" % fmt_rtt(rtt))
    else:
        print("        " + yellow("无响应") + "    可能被防护设备拦截 ICMP，不等于主机离线")

    print("\n  (2/2) 常用端口 TCP 探测 ...")
    results = scan_ports(ip, ALIVE_PROBE_PORTS, timeout=TCP_TIMEOUT)
    reached = [r for r in results if r["state"] in ("open", "closed")]
    for item in results:
        label = STATE_TEXT.get(item["state"], item["state"])
        mark = green(label) if item["state"] == "open" else (
            cyan(label) if item["state"] == "closed" else yellow(label)
        )
        print("        端口 %-6d %s" % (item["port"], mark))

    print("\n  " + "-" * 54)
    if alive or reached:
        detail = []
        if alive:
            detail.append("ICMP 有回应")
        if reached:
            detail.append("%d 个端口有响应" % len(reached))
        print("  [结论] " + green("服务器在线") + "    （%s）" % "，".join(detail))
    elif available:
        print("  [结论] " + red("未检测到存活迹象") + "    可能离线，或全部流量被静默丢弃")
    else:
        print("  [结论] " + red("无法判定") + "    缺少 ICMP 且所有 TCP 探测无响应")


# --------------------------------------------------------------------------
# 功能 2：服务器双向检测
# --------------------------------------------------------------------------
def feature_bidi():
    header(2, "服务器双向检测")
    ip = ask_ip()
    if ip is None:
        return
    port = ask_port("用于双向数据验证的端口", 80)

    print("\n  目标服务器 : %s:%d" % (bold(mask(ip)), port))
    print("  检测含义   : 去程（本机 → 服务器）与回程（服务器 → 本机）是否都通")
    print("  探测方式   : 均为本机直连，不经过任何第三方节点\n")

    # 1) 主机层
    print("  [1/3] 主机层：ICMP 回声往返")
    available, alive, rtt = icmp_ping(ip, timeout=2.0)
    if not available:
        icmp_verdict = "skip"
        print("        " + yellow("跳过") + "    本机缺少 ping 命令")
    elif alive:
        icmp_verdict = "ok"
        print("        " + green("往返成功") + "    请求送达且回声返回，延迟 %s" % fmt_rtt(rtt))
    else:
        icmp_verdict = "fail"
        print("        " + yellow("无回声") + "    去程或回程被拦截（常见于关闭 ICMP 的防护策略）")

    # 2) 传输层
    print("\n  [2/3] 传输层：TCP 三次握手")
    probe = tcp_probe(ip, port, timeout=3.0)
    tcp_verdict = "fail"
    if probe["state"] == "open":
        tcp_verdict = "ok"
        print("        " + green("握手成功") + "    SYN 到达服务器、SYN/ACK 回到本机，双向链路成立（%s）"
              % fmt_rtt(probe["rtt"] * 1000))
    elif probe["state"] == "closed":
        tcp_verdict = "half"
        print("        " + cyan("端口关闭，但服务器回了 RST") + "    回程可达，该端口没有服务监听")
        print("        建议换一个有服务在听的端口重测，例如 443、22 或业务端口")
    elif probe["state"] == "filtered":
        print("        " + red("无响应") + "    握手包被丢弃或端口被静默过滤，无法确认双向通路")
    elif probe["state"] == "unreachable":
        print("        " + red("网络不可达") + "    本机到该地址没有路由")
    else:
        print("        " + red("探测出错") + "    连接过程发生异常")

    # 3) 应用层
    print("\n  [3/3] 应用层：真实数据往返")
    if probe["state"] != "open":
        print("        " + yellow("跳过") + "    端口未开放，无法做数据层验证")
    else:
        sent, received = app_layer_exchange(ip, port, timeout=5.0)
        if received:
            print("        " + green("收到回包") + "    本机发出请求，服务器回了 %d 字节数据" % len(received))
            sniff = received.replace(b"\r\n", b" ")[:80]
            print("        回包开头：%s" % sniff.decode("iso-8859-1", "replace"))
        else:
            print("        " + yellow("没有收到数据") + "    端口虽开放，但未回任何内容（可能是非交互服务）")
        print("        （仅做 TCP 握手与一次只读请求，未发送任何敏感信息）")

    ok_count = sum(1 for v in (icmp_verdict, tcp_verdict) if v == "ok")
    print("\n  " + "-" * 54)
    if ok_count == 2:
        print("  [结论] " + green("双向通畅") + "    去程与回程都有明确应答")
    elif tcp_verdict == "ok":
        print("  [结论] " + green("双向连通") + "    握手成功，去程与回程都得到确认")
    elif tcp_verdict == "half":
        print("  [结论] " + cyan("回程可达") + "    服务器能回包给你，但该端口无服务，建议换个端口重测")
    elif icmp_verdict == "ok":
        print("  [结论] " + yellow("仅 ICMP 双向正常") + "    目标端口侧未确认")
    else:
        print("  [结论] " + red("未确认双向通路") + "    去程或回程至少一侧被阻断")


def app_layer_exchange(ip, port, timeout=5.0):
    """在已建立的连接上做一次数据往返，返回 (发出的数据, 收到的数据)。"""
    sock = None
    sent = b""
    received = b""
    try:
        sock = connect_tcp(ip, port, timeout)
        sock.settimeout(0.8)
        try:
            received = sock.recv(512)
        except (socket.timeout, OSError):
            received = b""
        if not received:
            host = str(ip) if ip.version == 4 else "[%s]" % ip
            sent = (
                "HEAD / HTTP/1.0\r\nHost: %s\r\n"
                "User-Agent: %s\r\nConnection: close\r\n\r\n" % (host, DEFAULT_UA)
            ).encode("ascii", "ignore")
            sock.settimeout(timeout)
            sock.sendall(sent)
            try:
                received = sock.recv(512)
            except (socket.timeout, OSError):
                received = b""
    except (OSError, ValueError):
        pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return sent, received


# --------------------------------------------------------------------------
# 功能 3：服务器端口检测
# --------------------------------------------------------------------------
def feature_ports():
    header(3, "服务器端口检测")
    ip = ask_ip()
    if ip is None:
        return

    print("\n  可直接回车使用内置常见端口清单，也可自定义：如 22,80,443,8000-8010")
    print("  （单次上限 %d 个端口，请只检测自有或已授权的服务器）" % MAX_PORTS_PER_RUN)
    ports = None
    while ports is None:
        try:
            raw = input("  端口列表 [回车 = 常见端口]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not raw:
            ports = sorted(PORT_NAMES)
            break
        try:
            ports = parse_port_list(raw)
        except ValueError as exc:
            print("  " + yellow("× %s" % exc))

    print("\n  目标服务器 : %s" % bold(mask(ip)))
    print("  探测端口数 : %d    方式：TCP 连接测试（直连，不经第三方）\n" % len(ports))

    results = scan_ports(ip, ports, timeout=TCP_TIMEOUT)
    open_ports = [r for r in results if r["state"] == "open"]
    closed_ports = [r for r in results if r["state"] == "closed"]
    filtered_ports = [r for r in results if r["state"] in ("filtered", "unreachable", "error")]

    for item in results:
        name = PORT_NAMES.get(item["port"], "")
        label = STATE_TEXT.get(item["state"], item["state"])
        if item["state"] == "open":
            status = green("[开放]")
        elif item["state"] == "closed":
            status = cyan("[关闭]")
        else:
            status = yellow("[%s]" % label)
        tail = ""
        if item["rtt"] is not None:
            tail = "    延迟 %s" % fmt_rtt(item["rtt"] * 1000)
        print("    %s 端口 %-6d %-14s%s" % (status, item["port"], name, tail))

    print("\n  " + "-" * 54)
    print("  统计：开放 %d 个 / 有响应但关闭 %d 个 / 无响应 %d 个"
          % (len(open_ports), len(closed_ports), len(filtered_ports)))

    exposed = [r["port"] for r in open_ports if r["port"] in SENSITIVE_PORTS]
    if exposed:
        print("\n  安全提醒：以下管理或数据库端口对外开放，建议限制来源 IP 或改为仅内网访问")
        for port in exposed:
            print("    - %d (%s)" % (port, PORT_NAMES.get(port, "")))
    elif open_ports:
        print("\n  未发现常见高危端口的对外开放记录")


# --------------------------------------------------------------------------
# 功能 4：服务器防护检测
# --------------------------------------------------------------------------
def feature_guard():
    header(4, "服务器防护检测")
    ip = ask_ip()
    if ip is None:
        return

    print("\n  目标服务器 : %s" % bold(mask(ip)))
    print("  检测内容   : ICMP 策略 / 丢包策略 / Web 防护特征 / 请求头差异 / 暴露面")
    print("  说明       : 只做只读探测，不发送攻击载荷，不修改目标任何状态\n")

    # 条目分级：guard = 发现防护迹象，risk = 暴露面风险，neutral = 中性观察
    findings = []

    # 1) ICMP 策略
    print("  [1/5] ICMP 响应策略")
    available, alive, rtt = icmp_ping(ip, timeout=2.0)
    if not available:
        print("        " + yellow("跳过") + "    本机缺少 ping 命令")
    elif alive:
        print("        " + cyan("允许 ICMP 回声") + "    延迟 %s（可能未针对 ICMP 做过滤）" % fmt_rtt(rtt))
        findings.append(("neutral", "允许 ICMP 回声，未见 ICMP 层面的过滤"))
    else:
        print("        " + green("ICMP 无响应") + "    常用于隐藏主机，可能存在包过滤策略")
        findings.append(("guard", "ICMP 被拦截，疑似存在包过滤 / 防火墙策略"))

    # 2) 丢包策略
    print("\n  [2/5] 未开放端口的响应方式（判断是否存在状态防火墙）")
    drop_results = scan_ports(ip, DROP_TEST_PORTS, timeout=TCP_TIMEOUT)
    states = [r["state"] for r in drop_results]
    for item in drop_results:
        print("        端口 %-6d %s" % (item["port"], STATE_TEXT.get(item["state"], item["state"])))
    if all(s == "filtered" for s in states):
        print("        " + green("全部静默丢包") + "    存在全量 drop 策略的可能性较高")
        findings.append(("guard", "高位端口全部无响应，疑似对未开放端口统一丢包（状态防火墙特征）"))
    elif any(s == "closed" for s in states):
        print("        " + cyan("返回 RST") + "    未开放端口直接拒绝，未见全量丢包策略")
        findings.append(("neutral", "未开放端口返回 RST，未见全量丢包策略"))
    else:
        print("        " + yellow("结果混合") + "    可能是部分端口被单独过滤")

    # 3) Web 防护特征
    print("\n  [3/5] Web 服务响应头特征（WAF / CDN）")
    try:
        raw_web = input("        指定 Web 端口（可留空，默认按 443/80/8443/8080 依次探测）: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raw_web = ""
    web_targets = [(443, True), (80, False), (8443, True), (8080, False)]
    if raw_web:
        try:
            web_targets = [(p, None) for p in parse_port_list(raw_web, limit=8)]
        except ValueError as exc:
            print("        " + yellow("× %s，改用默认端口" % exc))

    web_probe = None
    for port, use_tls in web_targets:
        result = (http_probe(ip, port, use_tls=use_tls, timeout=5.0)
                  if use_tls is not None else http_probe_any(ip, port, timeout=5.0))
        if result is not None:
            web_probe = result
            print("        探测 %s:%d ... 响应状态 %s" % (
                "https" if result["tls"] else "http", port,
                result["status"] if result["status"] else "无状态行（非标准 HTTP 服务）"))
            break
        print("        探测 %s:%d ... 无有效响应" % (
            "https" if use_tls else ("http/https" if use_tls is None else "http"), port))

    if web_probe is None:
        print("        " + yellow("未取到 HTTP 响应") + "    目标可能没有暴露 Web 服务，或端口被过滤")
    else:
        raw_head = web_probe["head"].lower().encode("iso-8859-1", "replace")
        detected = []
        for signature, name in WAF_SIGNATURES:
            if signature in raw_head and name not in detected:
                detected.append(name)
        if detected:
            print("        " + green("检测到防护特征") + "    %s" % "、".join(detected))
            findings.append(("guard", "响应头出现防护设备特征：%s" % "、".join(detected)))
        else:
            print("        " + cyan("未见已知 WAF / CDN 特征头") + "    可能未部署，或已隐藏标识")
        for key in ("server", "x-powered-by", "via", "set-cookie"):
            if key in web_probe["headers"]:
                print("        %s: %s" % (key, web_probe["headers"][key][:100]))
        if web_probe["status"] in (401, 403, 406, 429, 503):
            findings.append(("guard", "常规请求返回 %d，疑似存在访问控制或防护拦截" % web_probe["status"]))

    # 4) 请求头差异
    print("\n  [4/5] 请求头差异测试（判断是否配置了反爬或规则拦截）")
    if web_probe is None:
        print("        " + yellow("跳过") + "    没有可用的 HTTP 服务")
    else:
        port = web_probe["port"]
        use_tls = web_probe["tls"]
        normal = http_probe(ip, port, use_tls=use_tls, user_agent=DEFAULT_UA, timeout=5.0)
        empty = http_probe(ip, port, use_tls=use_tls, user_agent=None, timeout=5.0)
        normal_status = normal["status"] if normal else None
        empty_status = empty["status"] if empty else None
        print("        常规 User-Agent : %s" % (normal_status if normal_status else "无响应"))
        print("        空 User-Agent   : %s" % (empty_status if empty_status else "无响应"))
        if normal_status and empty_status and normal_status != empty_status:
            print("        " + green("存在差异") + "    服务器按请求头区别对待，疑似配置了访问规则")
            findings.append(("guard", "空 User-Agent 与常规请求返回不同状态码，疑似存在请求规则拦截"))
        elif normal_status and normal_status == empty_status:
            print("        " + cyan("无差异") + "    未从请求头差异上看到拦截行为")

    # 5) 暴露面
    print("\n  [5/5] 高危端口暴露面")
    risky = scan_ports(ip, sorted(SENSITIVE_PORTS), timeout=TCP_TIMEOUT)
    open_risky = [r["port"] for r in risky if r["state"] == "open"]
    if open_risky:
        print("        " + red("发现对外开放") + "    %s" % "、".join(
            "%d(%s)" % (p, PORT_NAMES.get(p, "")) for p in open_risky))
        findings.append(("risk", "以下高危端口对外开放：%s" % "、".join(str(p) for p in open_risky)))
    else:
        print("        " + cyan("未发现常见高危端口开放") + "    暴露面较小")

    # 汇总
    print("\n  " + "-" * 54)
    print("  [防护检测汇总]")
    if findings:
        for level, line in findings:
            prefix = {"guard": green("[防护]"), "risk": red("[风险]"), "neutral": cyan("[观察]")}[level]
            print("    %s %s" % (prefix, line))
    else:
        print("    · 本次探测未收集到可判断的条目")

    guard_count = sum(1 for level, _ in findings if level == "guard")
    if guard_count >= 2:
        print("    => 综合判断：" + green("检测到较明显的防护 / 加固迹象"))
    elif guard_count == 1:
        print("    => 综合判断：" + yellow("检测到部分防护特征"))
    else:
        print("    => 综合判断：" + yellow("未发现明显防护特征，建议核实是否需要加固"))
    print("\n  提示：以上结论基于常规探测特征推断，不能替代正式的安全评估。")


# --------------------------------------------------------------------------
# 功能 5：服务器IP解析
# --------------------------------------------------------------------------
def feature_resolve():
    header(5, "服务器IP解析")
    domain = ask_domain()
    if domain is None:
        return

    print("\n  域名       : %s" % bold(domain))
    print("  解析方式   : 用本机配置的 DNS 查询 A / AAAA 记录")
    print("  说明       : 该功能会把域名提交给你本机配置的 DNS 服务器（DNS 查询的必要行为），")
    print("               不经过任何第三方网站或公共 API；解析结果按功能用途明文显示\n")

    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        reason = {
            socket.EAI_NONAME: "域名不存在，或没有可用的 A / AAAA 记录",
            socket.EAI_AGAIN: "DNS 服务器暂时无响应，可稍后重试",
            socket.EAI_FAIL: "DNS 服务器返回了不可恢复的错误",
            socket.EAI_NODATA: "域名存在，但没有地址记录",
        }.get(exc.errno, "解析失败（%s）" % (exc.strerror or exc.errno))
        print("  " + red("[解析失败]") + "  %s" % reason)
        return
    except (OSError, UnicodeError) as exc:
        print("  " + red("[解析失败]") + "  %s" % exc)
        return
    elapsed_ms = (time.perf_counter() - start) * 1000

    ipv4, ipv6 = [], []
    for info in infos:
        address = info[4][0].split("%")[0]
        if ":" in address:
            if address not in ipv6:
                ipv6.append(address)
        elif address not in ipv4:
            ipv4.append(address)

    if ipv4:
        print("  IPv4 (A)    : %s" % bold(ipv4[0]))
        for address in ipv4[1:]:
            print("                %s" % address)
    if ipv6:
        print("  IPv6 (AAAA) : %s" % bold(ipv6[0]))
        for address in ipv6[1:]:
            print("                %s" % address)

    print("\n  " + "-" * 54)
    total = len(ipv4) + len(ipv6)
    if total:
        print("  [结论] " + green("解析成功") + "    共 %d 个地址（IPv4 %d / IPv6 %d），耗时 %.0f ms"
              % (total, len(ipv4), len(ipv6), elapsed_ms))
        print("         若要把结果送去前四项检测，请自行复制上面的地址（IP 输入不回显，注意核对）")
    else:
        print("  [结论] " + yellow("未解析到可用的 A / AAAA 地址"))
    print("  提示：标准库只能拿到地址列表，拿不到 TTL 与 CNAME 链路；")
    print("        如需这些信息，需安装第三方库 dnspython（pip install dnspython）后另行处理。")


# --------------------------------------------------------------------------
# 主程序
# --------------------------------------------------------------------------
def print_banner():
    print()
    print("  " + "=" * 54)
    print("    %s   v%s" % (APP_NAME, APP_VER))
    print("    仅限用于本人拥有或已获得书面授权的服务器")
    if UNMASK:
        print("    " + yellow("当前为明文显示模式（TOOLBOX_UNMASK=1）"))
    else:
        print("    IP 已脱敏显示，输入 q 可随时返回主菜单")
    print("  " + "=" * 54)


def main():
    clear_screen()
    print_banner()
    handlers = {
        "1": ("服务器存活检测", feature_alive),
        "2": ("服务器双向检测", feature_bidi),
        "3": ("服务器端口检测", feature_ports),
        "4": ("服务器防护检测", feature_guard),
        "5": ("服务器IP解析", feature_resolve),
    }
    while True:
        print("\n" + MENU)
        try:
            choice = input("  请输入数字选择功能: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\n  已退出程序，再见。")
            return
        if choice == "6":
            print("\n  已退出程序，再见。")
            return
        if choice in handlers:
            handlers[choice][1]()
            pause()
            clear_screen()
        else:
            print("  " + yellow("× 无效输入，请输入 1 - 6 之间的数字"))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  已退出程序，再见。")

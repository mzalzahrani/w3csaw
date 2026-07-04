"""Detection rules: built-in pack, custom user rules, and persistence.

A rule inspects one canonical field per record with a regex or literal
match. Threshold-based detections (rates, 404/500 volume, brute force)
live in engine.py because they need cross-record state.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

SEVERITIES = ("low", "medium", "high", "critical")

# Fields a rule may target. "url" is the fully decoded stem+query.
RULE_FIELDS = ("url", "uri_stem", "uri_query", "user_agent", "referer",
               "method", "c_ip", "username", "host", "raw")

CONFIG_DIR = os.environ.get(
    "IIS_HUNTER_HOME", os.path.join(os.path.expanduser("~"), ".iis_hunter"))
RULES_FILE = os.path.join(CONFIG_DIR, "rules.json")


@dataclass
class Rule:
    name: str
    severity: str
    description: str
    field: str = "url"
    match_type: str = "regex"          # "regex" or "literal"
    pattern: str = ""
    enabled: bool = True
    builtin: bool = False
    _compiled: Optional[re.Pattern] = None

    def compile(self) -> "Rule":
        if self.match_type == "regex":
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        return self

    def match(self, record: Dict[str, Any]) -> Optional[str]:
        """Return the matching value if this rule fires on the record."""
        value = record.get(self.field)
        if value is None:
            return None
        text = str(value)
        if self.match_type == "literal":
            return text if self.pattern.lower() in text.lower() else None
        found = self._compiled.search(text)
        return found.group(0) if found else None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data.pop("_compiled", None)
        return data


def _r(name: str, severity: str, description: str, pattern: str,
       fld: str = "url") -> Rule:
    return Rule(name=name, severity=severity, description=description,
                field=fld, match_type="regex", pattern=pattern,
                builtin=True).compile()


BUILTIN_RULES: List[Rule] = [
    # --- injection ---
    _r("sql_injection", "high",
       "SQL injection keywords in the request",
       r"union[\s/*+]+(?:all[\s/*+]+)?select|'\s*or\s+'?1'?\s*=\s*'?1|"
       r"xp_cmdshell|information_schema|sysobjects|waitfor\s+delay|"
       r"benchmark\s*\(|sleep\s*\(\d|load_file\s*\(|;\s*--\s|@@version"),
    _r("command_injection", "high",
       "OS command injection metacharacters followed by a command",
       r"(?:;|&&|\|\||%0a)\s*(?:cat|ls|id|pwd|whoami|ping|nc|bash|sh|dir|"
       r"type|ipconfig|netstat)\b|\$\((?:\w|/)|`\w+`"),
    _r("directory_traversal", "high",
       "Directory traversal sequence in the URL",
       r"\.\./|\.\.\\"),
    _r("encoded_traversal", "high",
       "URL-encoded or unicode-encoded traversal sequence",
       r"%2e%2e[%/\\]|%252e|\.%2e|%2e\.|%c0%af|%c1%9c|%c0%2e|%e0%80%ae",
       "raw"),
    _r("local_file_inclusion", "high",
       "Request references sensitive local files",
       r"etc/passwd|etc/shadow|boot\.ini|win\.ini|windows/system32|"
       r"proc/self/environ|sam\b.*system32|\\{2}windows\\{2}"),
    _r("remote_file_inclusion", "high",
       "Request parameter points at a remote file",
       r"(?:include|file|page|template|path|doc|document|conf|url|uri)="
       r"(?:https?|ftp|smb)://"),
    # --- web shells & suspicious handlers ---
    _r("web_shell_name", "critical",
       "Known web shell file name requested",
       r"/(?:shell|cmd|c99|c100|r57|b374k|wso|chopper|antsword|godzilla|"
       r"backdoor|door|hack|k8cmd|xxx)[\w-]*\.(?:aspx?|ashx|asmx|php|jsp)",
       "uri_stem"),
    _r("suspicious_aspx", "medium",
       ".aspx handler under an upload/temp/media directory",
       r"/(?:upload|uploads|temp|tmp|images|img|media|files|attachments|"
       r"aspnet_client)/[^/]*\.aspx", "uri_stem"),
    _r("suspicious_ashx", "medium",
       ".ashx handler under an upload/temp/media directory",
       r"/(?:upload|uploads|temp|tmp|images|img|media|files|attachments|"
       r"aspnet_client)/[^/]*\.ashx", "uri_stem"),
    _r("suspicious_asmx", "medium",
       ".asmx service under an upload/temp/media directory",
       r"/(?:upload|uploads|temp|tmp|images|img|media|files|attachments|"
       r"aspnet_client)/[^/]*\.asmx", "uri_stem"),
    _r("config_file_access", "high",
       "Attempt to read a .config file (web.config credential theft)",
       r"\.config$|web\.config", "uri_stem"),
    _r("backup_file_discovery", "medium",
       "Probing for backup or archive copies of site files",
       r"\.(?:bak|backup|old|orig|save|swp|zip|rar|7z|tar|gz|sql|mdb)$",
       "uri_stem"),
    # --- command execution tooling ---
    _r("command_execution", "high",
       "Command execution keywords in the query string",
       r"(?:cmd|exec|execute|command|run|shell)=|whoami|net\s+user|"
       r"net\s+localgroup|tasklist|systeminfo|quser\b|hostname\b.*&"),
    _r("powershell_execution", "critical",
       "PowerShell invocation or encoded command in the request",
       r"powershell|pwsh|-enc(?:odedcommand)?\s|frombase64string|"
       r"iex[\s(+]|invoke-(?:expression|webrequest|mimikatz)|downloadstring"),
    _r("cmd_execution", "high",
       "cmd.exe invocation in the request",
       r"cmd(?:\.exe)?(?:\s|\+|%20)*(?:/c|/k)|cmd\.exe"),
    _r("certutil_abuse", "critical",
       "certutil download/decode abuse (LOLBin)",
       r"certutil"),
    _r("bitsadmin_abuse", "critical",
       "bitsadmin transfer abuse (LOLBin)",
       r"bitsadmin"),
    _r("curl_wget_abuse", "high",
       "curl/wget download command inside the request",
       r"(?:^|[;&|=\s(])(?:curl|wget)(?:\.exe)?(?:\s|\+|%20)+(?:-|https?://)"),
    # --- scanners ---
    _r("scanner_nikto", "medium", "Nikto scanner user agent", r"nikto",
       "user_agent"),
    _r("scanner_sqlmap", "high", "sqlmap scanner user agent", r"sqlmap",
       "user_agent"),
    _r("scanner_nmap", "medium", "Nmap scripting engine user agent",
       r"nmap (?:scripting engine|nse)|mozilla/5\.0 \(compatible; nmap",
       "user_agent"),
    _r("scanner_acunetix", "medium", "Acunetix scanner user agent",
       r"acunetix", "user_agent"),
    _r("scanner_gobuster", "medium", "Gobuster scanner user agent",
       r"gobuster", "user_agent"),
    _r("scanner_ffuf", "medium", "ffuf fuzzer user agent", r"\bfuzz faster|ffuf",
       "user_agent"),
    _r("scanner_python_requests", "low", "Python Requests library user agent",
       r"python-requests|python-urllib|aiohttp", "user_agent"),
    _r("suspicious_user_agent", "medium",
       "Known offensive-tooling or anomalous user agent",
       r"masscan|zgrab|dirbuster|dirb\b|nessus|openvas|whatweb|nuclei|"
       r"havij|hydra|medusa|metasploit|burp|wpscan|joomscan|xspider",
       "user_agent"),
    # --- payload shape ---
    _r("long_url", "low",
       "Unusually long URL (possible overflow/obfuscated payload)",
       r"^.{2048,}", "url"),
    _r("long_query_string", "low",
       "Unusually long query string",
       r"^.{1024,}", "uri_query"),
    _r("encoded_payload", "medium",
       "Double-encoded, null-byte, or large base64 payload in the request",
       r"%25[0-9a-f]{2}|%00|%u00|(?:[A-Za-z0-9+/]{80,}={0,2})", "raw"),
    # --- product exploits ---
    _r("exchange_exploit", "critical",
       "Exchange ProxyLogon/ProxyShell/SSRF exploitation indicators",
       r"autodiscover\.json\?.*@|/ecp/[a-z0-9]{1,3}\.js|x-rps-cat|"
       r"x-anonresource|/powershell/\?x=|email=autodiscover|"
       r"/owa/auth/[a-z0-9]{1,8}\.aspx\?.*=|/ecp/ddi/ddiservice\.svc/setobject"),
    _r("sharepoint_exploit", "critical",
       "SharePoint exploitation indicators (ToolShell, CVE-2019-0604, ...)",
       r"/_layouts/1[56]/toolpane\.aspx|signout\.aspx.*toolpane|"
       r"/_vti_bin/client\.svc|businessdatametadatacatalog|"
       r"/_layouts/1[56]/(?:success|error)\.aspx\?.*=|picker\.aspx.*__cb"),
    _r("aspnet_exploit", "high",
       "ASP.NET exploitation indicators (Telerik, trace/elmah, padding oracle)",
       r"trace\.axd|elmah\.axd|telerik\.web\.ui|"
       r"webresource\.axd\?d=[\w-]{200,}|dialoghandler\.aspx\?.*dp="),
]


def default_config() -> Dict[str, Any]:
    return {"disabled_builtins": [], "custom_rules": []}


def load_config(path: str = RULES_FILE) -> Dict[str, Any]:
    if not os.path.isfile(path):
        return default_config()
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    data.setdefault("disabled_builtins", [])
    data.setdefault("custom_rules", [])
    return data


def save_config(config: Dict[str, Any], path: str = RULES_FILE) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)


def custom_rule_from_dict(data: Dict[str, Any]) -> Rule:
    name = str(data.get("name", "")).strip()
    if not name:
        raise ValueError("Rule name is required")
    severity = data.get("severity", "medium")
    if severity not in SEVERITIES:
        raise ValueError(f"Invalid severity: {severity!r}")
    fld = data.get("field", "url")
    if fld not in RULE_FIELDS:
        raise ValueError(f"Invalid field: {fld!r} (choose from {RULE_FIELDS})")
    match_type = data.get("match_type", "regex")
    if match_type not in ("regex", "literal"):
        raise ValueError("match_type must be 'regex' or 'literal'")
    pattern = str(data.get("pattern", ""))
    if not pattern:
        raise ValueError("Pattern is required")
    if match_type == "regex":
        re.compile(pattern)  # raises re.error with a useful message
    return Rule(name=name, severity=severity,
                description=str(data.get("description", "")), field=fld,
                match_type=match_type, pattern=pattern,
                enabled=bool(data.get("enabled", True)),
                builtin=False).compile()


def active_rules(config: Optional[Dict[str, Any]] = None) -> List[Rule]:
    """Built-in rules (minus disabled) plus enabled custom rules."""
    config = config if config is not None else load_config()
    disabled = set(config.get("disabled_builtins", []))
    rules = [rule for rule in BUILTIN_RULES
             if rule.name not in disabled]
    for data in config.get("custom_rules", []):
        try:
            rule = custom_rule_from_dict(data)
        except (ValueError, re.error):
            continue
        if rule.enabled:
            rules.append(rule)
    return rules

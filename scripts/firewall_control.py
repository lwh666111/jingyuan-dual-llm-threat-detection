from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
from typing import Any, Dict, List, Tuple


RULE_PREFIX = "TP_BLOCK_IP"


def normalize_ip_literal(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def firewall_rule_names(ip_text: str) -> Tuple[str, str]:
    suffix = re.sub(r"[^A-Za-z0-9_.:-]", "_", str(ip_text or "").strip())
    return f"{RULE_PREFIX}_IN_{suffix}", f"{RULE_PREFIX}_OUT_{suffix}"


def _ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _run_powershell(command: str, timeout: int = 20) -> Tuple[bool, str]:
    if os.name != "nt":
        return False, "firewall_supported_only_on_windows"
    prefix = "$ErrorActionPreference='Stop'; $OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); "
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", prefix + command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except Exception as exc:
        return False, str(exc)
    detail = "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part)
    return result.returncode == 0, detail


def firewall_status(ip_text: str) -> Dict[str, Any]:
    ip_value = normalize_ip_literal(ip_text)
    if not ip_value:
        return {"ip_address": "", "active": False, "inbound": False, "outbound": False, "error": "invalid_ip"}
    inbound, outbound = firewall_rule_names(ip_value)
    script = (
        f"$names=@({_ps_quote(inbound)},{_ps_quote(outbound)}); "
        "$rows=@(); foreach($name in $names){ "
        "$rule=Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue; "
        "if($rule){$addr=$rule | Get-NetFirewallAddressFilter; "
        "$rows += [pscustomobject]@{Name=$rule.Name;Enabled=[string]$rule.Enabled;Direction=[string]$rule.Direction;Action=[string]$rule.Action;RemoteAddress=($addr.RemoteAddress -join ',')}}}; "
        "$rows | ConvertTo-Json -Compress"
    )
    ok, output = _run_powershell(script)
    if not ok:
        return {"ip_address": ip_value, "active": False, "inbound": False, "outbound": False, "error": output}
    try:
        parsed = json.loads(output) if output else []
    except json.JSONDecodeError:
        parsed = []
    rows: List[Dict[str, Any]] = parsed if isinstance(parsed, list) else ([parsed] if isinstance(parsed, dict) else [])
    active_names = {
        str(row.get("Name") or "")
        for row in rows
        if str(row.get("Enabled") or "").lower() == "true" and str(row.get("Action") or "").lower() == "block"
    }
    has_inbound = inbound in active_names
    has_outbound = outbound in active_names
    return {
        "ip_address": ip_value,
        "active": has_inbound and has_outbound,
        "inbound": has_inbound,
        "outbound": has_outbound,
        "rules": rows,
        "error": "",
    }


def firewall_status_many(ip_values: List[str]) -> Dict[str, Dict[str, Any]]:
    normalized = list(dict.fromkeys(normalize_ip_literal(value) for value in ip_values))
    normalized = [value for value in normalized if value]
    if not normalized:
        return {}
    if os.name != "nt":
        return {value: {"ip_address": value, "active": False, "inbound": False, "outbound": False, "error": "unsupported_platform"} for value in normalized}
    script = (
        f"$rules=Get-NetFirewallRule -Name {_ps_quote(RULE_PREFIX + '_*')} -ErrorAction SilentlyContinue; "
        "$rows=@(); foreach($rule in $rules){$rows += [pscustomobject]@{Name=$rule.Name;Enabled=[string]$rule.Enabled;Direction=[string]$rule.Direction;Action=[string]$rule.Action}}; "
        "$rows | ConvertTo-Json -Compress"
    )
    ok, output = _run_powershell(script)
    if not ok:
        return {value: {"ip_address": value, "active": False, "inbound": False, "outbound": False, "error": output} for value in normalized}
    try:
        parsed = json.loads(output) if output else []
    except json.JSONDecodeError:
        parsed = []
    rows: List[Dict[str, Any]] = parsed if isinstance(parsed, list) else ([parsed] if isinstance(parsed, dict) else [])
    active_names = {
        str(row.get("Name") or "")
        for row in rows
        if str(row.get("Enabled") or "").lower() == "true" and str(row.get("Action") or "").lower() == "block"
    }
    result: Dict[str, Dict[str, Any]] = {}
    for value in normalized:
        inbound, outbound = firewall_rule_names(value)
        has_inbound = inbound in active_names
        has_outbound = outbound in active_names
        result[value] = {
            "ip_address": value,
            "active": has_inbound and has_outbound,
            "inbound": has_inbound,
            "outbound": has_outbound,
            "error": "",
        }
    return result


def firewall_block_ip(ip_text: str) -> Tuple[bool, str]:
    ip_value = normalize_ip_literal(ip_text)
    if not ip_value:
        return False, "invalid_or_empty_ip"
    inbound, outbound = firewall_rule_names(ip_value)
    script = (
        f"$names=@({_ps_quote(inbound)},{_ps_quote(outbound)}); "
        "foreach($name in $names){Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop}; "
        f"New-NetFirewallRule -Name {_ps_quote(inbound)} -DisplayName {_ps_quote(inbound)} -Direction Inbound -Action Block -RemoteAddress {_ps_quote(ip_value)} -Profile Any -Enabled True | Out-Null; "
        f"New-NetFirewallRule -Name {_ps_quote(outbound)} -DisplayName {_ps_quote(outbound)} -Direction Outbound -Action Block -RemoteAddress {_ps_quote(ip_value)} -Profile Any -Enabled True | Out-Null; "
        "$verified=@($names | ForEach-Object {Get-NetFirewallRule -Name $_ -ErrorAction Stop | Where-Object {$_.Enabled -eq 'True' -and $_.Action -eq 'Block'}}); "
        "if($verified.Count -ne 2){throw 'firewall_rule_verification_failed'}"
    )
    ok, detail = _run_powershell(script)
    return (True, "") if ok else (False, detail)


def firewall_unblock_ip(ip_text: str) -> Tuple[bool, str]:
    ip_value = normalize_ip_literal(ip_text)
    if not ip_value:
        return False, "invalid_or_empty_ip"
    inbound, outbound = firewall_rule_names(ip_value)
    script = (
        f"$names=@({_ps_quote(inbound)},{_ps_quote(outbound)}); "
        "foreach($name in $names){Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop}; "
        "$remaining=@($names | ForEach-Object {Get-NetFirewallRule -Name $_ -ErrorAction SilentlyContinue}); "
        "if($remaining.Count -gt 0){throw ('firewall_rule_removal_verification_failed: ' + (($remaining | Select-Object -ExpandProperty Name) -join ','))}"
    )
    ok, detail = _run_powershell(script)
    return (True, "") if ok else (False, detail)


def is_safe_automatic_target(ip_text: str, allow_private: bool = False) -> bool:
    value = normalize_ip_literal(ip_text)
    if not value:
        return False
    ip_value = ipaddress.ip_address(value)
    if ip_value.is_loopback or ip_value.is_unspecified or ip_value.is_multicast or ip_value.is_link_local:
        return False
    if not allow_private and (ip_value.is_private or ip_value.is_reserved):
        return False
    return True

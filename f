"""FortiManager API client.

JSON-RPC client for FortiManager with high-level helpers for managing
ADOMs, devices, firewall policies, IPS profiles, and Excel reporting.
"""
from __future__ import annotations

import traceback
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Iterable, Optional

import requests
import urllib3
from openpyxl import Workbook
from openpyxl.cell import MergedCell
from openpyxl.styles import Alignment, Font, PatternFill

from bookmark.settings import (
    FORTIMANAGER_HOST_URL,
    FORTIMANAGER_USERNAME,
    get_fortimanager_password,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Excel style constants (defined once, reused by every report)
# ---------------------------------------------------------------------------
_HEADER_FILL = PatternFill(start_color="D3D3D3", end_color="D3D3D3", fill_type="solid")
_FAIL_FILL = PatternFill(start_color="FF0000", end_color="FF0000", fill_type="solid")
_OK_FILL = PatternFill(start_color="90EE90", end_color="90EE90", fill_type="solid")
_HEADER_FONT = Font(bold=True)
_TITLE_FONT = Font(bold=True, size=14)
_CENTER = Alignment(horizontal="center", vertical="center")

POLICY_FIELDS = [
    "obj seq", "status", "policyid", "srcintf", "dstintf",
    "srcaddr", "dstaddr", "action", "schedule", "service",
    "users", "logtraffic", "nat", "name", "comments",
    "extra info", "ips-sensor",
]

# IPS profile cleaning rules (used when copying profiles between ADOMs)
_IPS_FORBIDDEN_FIELDS = ("oid", "obj seq", "last-modified")
_IPS_7_0_ALLOWED_FIELDS = {
    "action", "application", "log", "status",
    "os", "protocol", "quarantine", "severity",
}


class FMNapi:
    """Thin client around the FortiManager JSON-RPC API."""

    # ------------------------------------------------------------------ init
    def __init__(self, verify: bool = False) -> None:
        self.base_url = FORTIMANAGER_HOST_URL
        self.username = FORTIMANAGER_USERNAME
        self.password = get_fortimanager_password()

        # One Session for the whole client → keepalive + connection reuse.
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update({"Content-Type": "application/json"})
        self.session.proxies = {"https": None}

    # =================================================================
    #  Low-level transport
    # =================================================================
    def _request(
        self,
        method: str,
        endpoint: str,
        session_id: Optional[str] = None,
        *,
        data: Any = None,
        **extra_params: Any,
    ) -> dict:
        """Send a JSON-RPC request and return the parsed JSON response.

        Args:
            method: ``get``, ``add``, ``update``, ``set``, ``exec``, ``delete``...
            endpoint: API path (e.g. ``/sys/login/user``).
            session_id: session token; ``None`` only during login.
            data: optional payload placed inside ``params[0]['data']``.
            **extra_params: extra keys merged alongside ``url`` (e.g. ``fields``,
                ``option``, ``verbose``).
        """
        params: dict[str, Any] = {"url": endpoint, **extra_params}
        if data is not None:
            params["data"] = data

        payload: dict[str, Any] = {
            "id": 1,
            "method": method,
            "params": [params],
            "verbose": 1,
        }
        if session_id is not None:
            payload["session"] = session_id

        return self.session.post(self.base_url, json=payload).json()

    # =================================================================
    #  Response helpers
    # =================================================================
    @staticmethod
    def _data(response: dict, default: Any = None) -> Any:
        """Return ``response['result'][0]['data']`` or ``default`` (``[]``)."""
        if default is None:
            default = []
        return response.get("result", [{}])[0].get("data", default)

    @staticmethod
    def _status(response: dict) -> dict:
        return response.get("result", [{}])[0].get("status", {})

    @classmethod
    def _is_ok(cls, response: dict) -> bool:
        return cls._status(response).get("code") == 0

    @staticmethod
    def _is_drop_or_deny(action: Optional[str]) -> bool:
        return (action or "").lower() in ("drop", "deny")

    # =================================================================
    #  Authentication
    # =================================================================
    def login(self) -> dict:
        """Authenticate and obtain a session token (stored in ``result[0]['session']``)."""
        return self._request(
            "exec", "/sys/login/user",
            data={"user": self.username, "passwd": self.password},
        )

    def logout(self, session_id: str) -> dict:
        return self._request("exec", "/sys/logout", session_id)

    # =================================================================
    #  ADOMs
    # =================================================================
    def get_adom_members(self, session_id: str) -> dict:
        return self._request("get", "/dvmdb/adom", session_id, option="object member")

    def get_adom_names(self, session_id: str) -> list[str]:
        return [item["name"] for item in self._data(self.get_adom_members(session_id))]

    def get_adom_list_info(self, session_id: str) -> list[dict]:
        """Per-ADOM list of packages and their members, expanding HA pairs."""
        adoms = self._data(self.get_adom_members(session_id))
        result: list[dict] = []

        for item in adoms:
            adom_name = item["name"]
            for package in self._data(self.get_package_details(session_id, adom_name)):
                scope_members = package.get("scope member") or []
                if not scope_members:
                    continue
                expanded: list[dict] = []
                for member in scope_members:
                    if "ha" in member["name"].lower():
                        expanded.extend(self._expand_ha_member(session_id, member))
                    else:
                        expanded.append(member)
                result.append({package["name"]: expanded})
        return result

    def _expand_ha_member(self, session_id: str, member: dict) -> list[dict]:
        device = self._data(self.get_device_details(session_id, member["name"]),
                            default={}) or {}
        return [
            {"name": fw["name"], "vdom": member["vdom"]}
            for fw in (device.get("ha_slave") or [])
        ]

    # =================================================================
    #  Workspace (lock / commit / unlock)
    # =================================================================
    def lock_adom(self, session_id: str, adom: str) -> dict:
        return self._request("exec", f"/dvmdb/adom/{adom}/workspace/lock", session_id)

    def unlock_adom(self, session_id: str, adom: str) -> dict:
        return self._request("exec", f"/dvmdb/adom/{adom}/workspace/unlock", session_id)

    def commit_adom(self, session_id: str, adom: str) -> dict:
        return self._request("exec", f"/dvmdb/adom/{adom}/workspace/commit", session_id)

    @contextmanager
    def adom_workspace(self, session_id: str, adom: str, *, commit: bool = True,
                       verbose: bool = True):
        """Lock the ADOM, run the block, optionally commit, always unlock."""
        lock = self.lock_adom(session_id, adom)
        if verbose:
            print(f"Lock ADOM ({adom}) response: {lock}")
        try:
            yield lock
            if commit:
                resp = self.commit_adom(session_id, adom)
                if verbose:
                    print(f"Commit ADOM ({adom}) response: {resp}")
        finally:
            resp = self.unlock_adom(session_id, adom)
            if verbose:
                print(f"Unlock ADOM ({adom}) response: {resp}")

    # =================================================================
    #  Devices
    # =================================================================
    def get_devices(self, session_id: str) -> dict:
        return self._request("get", "/dvmdb/device", session_id)

    def get_device_details(self, session_id: str, device: str) -> dict:
        return self._request("get", f"/dvmdb/device/{device}", session_id)

    def get_ha_firewalls(self, session_id: str) -> list[str]:
        """All HA-slave device names."""
        return [
            fw["name"]
            for item in self._data(self.get_devices(session_id))
            if item.get("ha_slave")
            for fw in item["ha_slave"]
        ]

    def get_all_devices(self, session_id: str) -> list[str]:
        """All device/vdom names, including HA members."""
        names: list[str] = []
        for item in self._data(self.get_devices(session_id)):
            if item.get("ha_slave"):
                names.extend(fw["name"] for fw in item["ha_slave"])
            else:
                names.extend(vdom["devid"] for vdom in item.get("vdom") or [])
        return names

    def get_ha_groups(self, session_id: str) -> list[dict]:
        """List of HA groups with their member devices."""
        groups: dict[str, set[str]] = {}
        for device in self.get_ha_firewalls(session_id):
            data = self._data(self.get_device_details(session_id, device),
                              default={}) or {}
            group_name = data.get("ha_group_name")
            if not group_name:
                continue
            members = groups.setdefault(group_name, set())
            if data.get("name"):
                members.add(data["name"])
            for fw in data.get("ha_slave") or []:
                if fw.get("name"):
                    members.add(fw["name"])
        return [{"ha_group_name": k, "devices": sorted(v)} for k, v in groups.items()]

    # =================================================================
    #  Policy packages and rules
    # =================================================================
    def get_package_details(self, session_id: str, adom: str) -> dict:
        return self._request("get", f"/pm/pkg/adom/{adom}", session_id)

    def get_all_policy_packages_in_adom(self, session_id: str, adom: str) -> list[dict]:
        return [
            {
                "adom": adom,
                "name": p.get("name", "N/A"),
                "type": p.get("type", "N/A"),
                "description": p.get("description", "N/A"),
                "scope_members": p.get("scope member", []),
                "version": p.get("version", "N/A"),
                "status": p.get("status", "N/A"),
            }
            for p in self._data(self.get_package_details(session_id, adom))
        ]

    def get_policy_package_details(self, session_id: str, adom: str,
                                   policy_package: str) -> dict:
        return self._request(
            "get",
            f"/pm/config/adom/{adom}/pkg/{policy_package}/firewall/policy",
            session_id,
            fields=POLICY_FIELDS,
        )

    def get_policy_details(self, session_id: str, adom: str,
                           policy_package: str, policy_id: int) -> dict:
        return self._request(
            "get",
            f"/pm/config/adom/{adom}/pkg/{policy_package}/firewall/policy/{policy_id}",
            session_id,
        )

    def update_rule(self, session_id: str, adom: str, policy_package: str,
                    rule_id: int, update_data: dict) -> dict:
        return self._request(
            "update",
            f"/pm/config/adom/{adom}/pkg/{policy_package}/firewall/policy/{rule_id}",
            session_id,
            data=update_data,
        )

    def update_rule_with_ips_sensor(self, session_id: str, adom: str,
                                    policy_package: str, rule_id: int,
                                    ips_sensor: str) -> dict:
        """Apply an IPS profile to a rule and enable UTM/log-traffic."""
        response = self.update_rule(session_id, adom, policy_package, rule_id, {
            "ips-sensor": ips_sensor,
            "utm-status": "enable",
            "logtraffic": "utm",
            "logtraffic-start": "enable",
        })
        print(response)
        return response

    # =================================================================
    #  Service / address objects
    # =================================================================
    def get_service_group_details(self, session_id: str, adom: str,
                                  group_name: str) -> Optional[dict]:
        """Service-group details, falling back to custom service if needed."""
        endpoints = (
            f"/pm/config/adom/{adom}/obj/firewall/service/group/{group_name}",
            f"/pm/config/adom/{adom}/obj/firewall/service/custom/{group_name}",
        )
        try:
            response: dict = {}
            for endpoint in endpoints:
                response = self._request("get", endpoint, session_id)
                if response.get("result"):
                    return response
            return response
        except Exception as exc:  # noqa: BLE001 - upstream errors are mixed
            print(f"Error getting service group details for {group_name}: {exc}")
            return None

    def get_address_group_details(self, session_id: str, adom: str,
                                  group_name: str) -> dict:
        return self._request(
            "get",
            f"/pm/config/adom/{adom}/obj/firewall/addrgrp/{group_name}",
            session_id,
        )

    def update_address_group(self, session_id: str, adom: str, group_name: str,
                             new_members: list[str]) -> dict:
        with self.adom_workspace(session_id, adom):
            return self._request(
                "update",
                f"/pm/config/adom/{adom}/obj/firewall/addrgrp/{group_name}",
                session_id,
                data={"member": new_members},
            )

    # =================================================================
    #  Scripts
    # =================================================================
    def get_script_details(self, session_id: str, adom: str) -> dict:
        return self._request("get", "/dvmdb/script", session_id, data={"adom": adom})

    def execute_script(self, session_id: str, adom: str, policy_package: str,
                       device: str, vdom: str, script: str) -> dict:
        return self._request(
            "exec",
            "/dvmdb/script/execute",
            session_id,
            data={
                "adom": adom,
                "package": policy_package,
                "scope": [{"name": device, "vdom": vdom}],
                "script": script,
            },
        )

    # =================================================================
    #  Detect rules with problematic services
    # =================================================================
    def get_rules_with_problematic_services(
        self,
        session_id: str,
        adom: str,
        policy_package: str,
        problematic_services: Iterable[str],
        ips_profile_mapping: dict[str, list[str]],
    ) -> list[dict]:
        """Return rules whose services match ``problematic_services``.

        Recurses one level into service groups so indirect matches are caught.
        """
        problematic = set(problematic_services)
        policies = self._data(
            self.get_policy_package_details(session_id, adom, policy_package))
        affected: list[dict] = []

        for policy in policies:
            if self._is_drop_or_deny(policy.get("action")):
                continue

            rule_services = policy.get("service") or []
            problematic_in_rule, expanded = self._collect_problematic_services(
                session_id, adom, rule_services, problematic)
            if not problematic_in_rule:
                continue

            applicable = sorted({
                profile
                for service in problematic_in_rule
                for profile in ips_profile_mapping.get(service, [])
            })
            ips_profile = policy.get("ips-sensor")

            affected.append({
                "adom": adom,
                "policy_package": policy_package,
                "policy_id": policy["policyid"],
                "policy_name": policy.get("name", "N/A"),
                "rule_id": policy.get("policyid", ""),
                "rule_name": policy.get("name", "N/A"),
                "problematic_services": problematic_in_rule,
                "applicable_ips_profiles": applicable,
                "src": policy.get("srcaddr", []),
                "dst": policy.get("dstaddr", []),
                "rule_services": rule_services,
                "action": (policy.get("action") or "").lower(),
                "ips_status": "Yes" if ips_profile else "No",
                "applied_ips_profile": ips_profile,
                "expanded_services": expanded,
            })
        return affected

    def _collect_problematic_services(
        self, session_id: str, adom: str,
        rule_services: list[str], problematic: set[str],
    ) -> tuple[list[str], list[str]]:
        """Return ``(found_services, expansion_log)`` for one rule."""
        found: list[str] = []
        expanded: list[str] = []

        for service in rule_services:
            if service in problematic:
                found.append(service)
                continue
            try:
                group = self.get_service_group_details(session_id, adom, service)
                if not group or not group.get("result"):
                    print(f"Warning: Could not get details for group {service}")
                    continue
                results = group["result"]
                if not isinstance(results, list) or not results:
                    print(f"Warning: Unexpected structure in group {service} details")
                    continue
                group_data = results[0].get("data") or {}
                if not isinstance(group_data, dict):
                    print(f"Warning: Group {service} data is not a dictionary")
                    continue
                for member in group_data.get("member") or []:
                    if member in problematic:
                        found.append(member)
                        expanded.append(f"{service} -> {member}")
            except Exception as exc:  # noqa: BLE001
                print(f"Error processing group {service}: {exc}")
        return found, expanded

    # =================================================================
    #  High-level operations: apply / remove IPS sensors
    # =================================================================
    def apply_ips_to_rules(self, session_id: str, adom: str, policy_package: str,
                           problematic_services: Iterable[str],
                           ips_profile_mapping: dict[str, list[str]]) -> list[dict]:
        """Apply IPS sensors to all rules with problematic services.

        Returns one result dict per rule that was actually touched.
        """
        affected = self.get_rules_with_problematic_services(
            session_id, adom, policy_package, problematic_services, ips_profile_mapping)

        updated: list[dict] = []
        with self.adom_workspace(session_id, adom):
            for policy in affected:
                result = self._apply_one(session_id, adom, policy_package, policy)
                if result is not None:
                    updated.append(result)
        return updated

    def _apply_one(self, session_id: str, adom: str, policy_package: str,
                   policy: dict) -> Optional[dict]:
        base = {"rule_id": policy["rule_id"], "rule_name": policy["rule_name"]}

        if self._is_drop_or_deny(policy.get("action")):
            return {**base, "ips_sensor_applied": "N/A (drop/deny action)",
                    "status": "Skipped"}

        if policy["ips_status"] != "No" or not policy["applicable_ips_profiles"]:
            return None  # nothing to do, don't include in report

        profiles = policy["applicable_ips_profiles"]
        ips_sensor = "NETSEC_IPS_ALL_MONITOR" if len(profiles) > 1 else profiles[0]

        response = self.update_rule_with_ips_sensor(
            session_id, adom, policy_package, policy["rule_id"], ips_sensor)

        if self._is_ok(response):
            return {**base, "ips_sensor_applied": ips_sensor, "status": "Success"}
        return {**base,
                "ips_sensor_applied": ips_sensor,
                "status": "Failed",
                "error": self._status(response).get("message")}

    def remove_ips_from_rules_except(
        self, session_id: str, adom: str, policy_package: str,
        excluded_profiles: Optional[Iterable[str]] = None,
    ) -> list[dict]:
        """Remove IPS profiles from every rule in a package except listed exclusions."""
        excluded = set(excluded_profiles or [])
        policies = self._data(
            self.get_policy_package_details(session_id, adom, policy_package))

        updated: list[dict] = []
        with self.adom_workspace(session_id, adom):
            for policy in policies:
                result = self._remove_one(session_id, adom, policy_package, policy, excluded)
                if result is not None:
                    updated.append(result)
        return updated

    def _remove_one(self, session_id: str, adom: str, policy_package: str,
                    policy: dict, excluded: set[str]) -> Optional[dict]:
        rule_id = policy.get("policyid", "")
        rule_name = policy.get("name", "N/A")
        ips_profile = policy.get("ips-sensor")
        if isinstance(ips_profile, list) and ips_profile:
            ips_profile = ips_profile[0]
        base = {"rule_id": rule_id, "rule_name": rule_name}

        if self._is_drop_or_deny(policy.get("action")):
            return {**base, "ips_sensor_removed": "N/A (drop/deny action)",
                    "status": "Skipped"}

        if not ips_profile:
            return None

        if "block" in str(ips_profile).lower():
            print(f"Not removing {ips_profile}")
            print(policy)
            return {**base,
                    "ips_sensor_removed":
                        "N/A (excluded profile is already a blocking profile)",
                    "status": "Skipped",
                    "current_ips_sensor": ips_profile}

        if ips_profile in excluded:
            return {**base,
                    "ips_sensor_removed": "N/A (excluded profile)",
                    "status": "Skipped",
                    "current_ips_sensor": ips_profile}

        update_data: dict[str, Any] = {"ips-sensor": None, "utm-status": "disable"}
        for key in ("logtraffic", "logtraffic-start"):
            if policy.get(key):
                update_data[key] = policy[key]

        response = self.update_rule(session_id, adom, policy_package, rule_id, update_data)
        if self._is_ok(response):
            return {**base, "ips_sensor_removed": ips_profile, "status": "Success"}
        return {**base,
                "ips_sensor_removed": ips_profile,
                "status": "Failed",
                "error": self._status(response).get("message")}

    # =================================================================
    #  IPS profile cloning between ADOMs
    # =================================================================
    @staticmethod
    def _clean_entry(entry: dict, target_version: str) -> dict:
        """Strip read-only fields and fields not accepted by the target FortiOS version."""
        for k in _IPS_FORBIDDEN_FIELDS:
            entry.pop(k, None)

        if target_version.startswith("7.0"):
            entry.pop("id", None)
            entry = {k: v for k, v in entry.items() if k in _IPS_7_0_ALLOWED_FIELDS}
        entry.setdefault("status", "enable")
        return entry

    @classmethod
    def _build_clean_data(cls, original: dict, target_version: str) -> dict:
        """Build the payload for an ``add`` IPS-profile call against ``target_version``."""
        clean: dict[str, Any] = {
            "name": original["name"],
            "comment": original.get("comment", ""),
            "entries": [
                cls._clean_entry(e.copy(), target_version)
                for e in original.get("entries", [])
            ],
            "extended-log": original.get("extended-log", "disable"),
        }
        if target_version.startswith("7.2"):
            clean["block-malicious-url"] = original.get("block-malicious-url", "disable")
            clean["scan-botnet-connections"] = original.get("scan-botnet-connections", "disable")
        if original.get("replacemsg-group"):
            clean["replacemsg-group"] = original["replacemsg-group"]
        return clean

    def copy_ips_profiles(
        self,
        session_id: str,
        source_adom: str,
        target_adom: str,
        profile_names: Optional[Iterable[str]] = None,
        copy_all: bool = False,
        target_version: str = "7.2",
        overwrite_existing: bool = False,
    ) -> dict:
        """Copy IPS sensor profiles between ADOMs."""
        if not profile_names and not copy_all:
            raise ValueError("Must specify profile_names or set copy_all=True")

        results: dict[str, Any] = {
            "source_adom": source_adom,
            "target_adom": target_adom,
            "target_version": target_version,
            "total_profiles": 0,
            "copied_profiles": 0,
            "updated_profiles": 0,
            "skipped_profiles": 0,
            "failed_profiles": 0,
            "details": [],
            "timestamp": datetime.now().isoformat(),
        }
        log = results["details"].append
        log(f"Starting IPS profile copy {source_adom} -> {target_adom} "
            f"(target version: {target_version})")

        try:
            # Source is locked but never committed; target locks + commits.
            with self.adom_workspace(session_id, source_adom, commit=False), \
                    self.adom_workspace(session_id, target_adom):

                source_profiles = self._data(self._request(
                    "get", f"/pm/config/adom/{source_adom}/obj/ips/sensor", session_id))
                results["total_profiles"] = len(source_profiles)
                log(f"Total profiles found: {results['total_profiles']}")

                if copy_all:
                    profiles_to_copy = source_profiles
                    log("Copying all IPS profiles")
                else:
                    name_set = set(profile_names or [])
                    profiles_to_copy = [p for p in source_profiles if p["name"] in name_set]
                    log(f"Copying specific profiles: {', '.join(name_set)}")

                if not profiles_to_copy:
                    log("No profiles found to copy")
                    return results

                target_profiles = self._data(self._request(
                    "get", f"/pm/config/adom/{target_adom}/obj/ips/sensor", session_id))
                target_names = {p["name"] for p in target_profiles}
                log(f"Existing profiles in target: {len(target_names)}")

                for profile in profiles_to_copy:
                    self._copy_one_profile(
                        session_id, source_adom, target_adom, profile,
                        target_names, target_version, overwrite_existing, results)
        except Exception as exc:  # noqa: BLE001
            log(f"\n✗ General error: {exc}")
            log(f"Error trace: {traceback.format_exc()}")

        print(results)
        return results

    def _copy_one_profile(self, session_id: str, source_adom: str, target_adom: str,
                          profile: dict, target_names: set[str], target_version: str,
                          overwrite_existing: bool, results: dict) -> None:
        log = results["details"].append
        name = profile["name"]
        log(f"\nProcessing profile: {name}")

        try:
            if name in target_names and not overwrite_existing:
                results["skipped_profiles"] += 1
                log(f"  Profile {name} already exists in target - skipping")
                return

            details = self._request(
                "get", f"/pm/config/adom/{source_adom}/obj/ips/sensor/{name}", session_id)
            if not details.get("result"):
                raise RuntimeError(f"Could not get details for profile {name}")
            original = details["result"][0]["data"]
            clean = self._build_clean_data(original, target_version)

            method = "update" if name in target_names else "add"
            endpoint = f"/pm/config/adom/{target_adom}/obj/ips/sensor"
            if method == "update":
                endpoint = f"{endpoint}/{name}"

            response = self._request(method, endpoint, session_id, data=clean)
            if self._is_ok(response):
                if method == "add":
                    results["copied_profiles"] += 1
                    log(f"  ✓ Profile copied successfully: {name}")
                else:
                    results["updated_profiles"] += 1
                    log(f"  ✓ Profile updated successfully: {name}")
            else:
                results["failed_profiles"] += 1
                log(f"  ✗ Error copying profile {name}: "
                    f"{self._status(response).get('message', 'Unknown error')}")
        except Exception as exc:  # noqa: BLE001
            results["failed_profiles"] += 1
            log(f"  ✗ Error processing profile {name}: {exc}")
            log(f"  Error trace: {traceback.format_exc()}")

    # =================================================================
    #  Excel report helpers
    # =================================================================
    @staticmethod
    def _default_filename(prefix: str) -> str:
        return f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

    @staticmethod
    def _join(value: Any) -> str:
        """Join lists/tuples with ', '. Pass strings through unchanged.

        Avoids the bug where ``', '.join(string)`` separates the string
        character-by-character.
        """
        if isinstance(value, (list, tuple, set)):
            return ", ".join(str(v) for v in value)
        return "" if value is None else str(value)

    @staticmethod
    def _write_header_row(ws, headers: list[str], row: int = 1) -> None:
        for col_num, header in enumerate(headers, 1):
            cell = ws.cell(row=row, column=col_num, value=header)
            cell.font = _HEADER_FONT
            cell.alignment = _CENTER
            cell.fill = _HEADER_FILL

    @staticmethod
    def _autosize_columns(ws, max_width: int = 100) -> None:
        for column in ws.columns:
            column_letter = None
            max_length = 0
            for cell in column:
                if isinstance(cell, MergedCell):
                    continue
                if column_letter is None:
                    column_letter = cell.column_letter
                if cell.value is not None:
                    max_length = max(max_length, len(str(cell.value)))
            if column_letter:
                ws.column_dimensions[column_letter].width = min(max_length + 2, max_width)

    @staticmethod
    def _write_title_block(ws, title: str, last_col: str = "D") -> None:
        ws.merge_cells(f"A1:{last_col}1")
        ws["A1"] = title
        ws["A1"].font = _TITLE_FONT
        ws["A1"].alignment = _CENTER

        ws.merge_cells(f"A2:{last_col}2")
        ws["A2"] = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        ws["A2"].alignment = _CENTER

    @staticmethod
    def _write_details_block(ws, start_row: int, details: Iterable[str],
                             max_width: int = 100) -> int:
        """Write a list of strings in column A, wrapping long lines."""
        row = start_row
        for detail in details:
            chunks = [detail[i:i + max_width] for i in range(0, len(detail), max_width)] \
                or [detail]
            for chunk in chunks:
                ws.cell(row=row, column=1, value=chunk)
                row += 1
        return row

    def _write_tabular_report(self, filename: Optional[str], sheet_title: str,
                              prefix: str, headers: list[str],
                              rows: Iterable[tuple], row_styler=None) -> str:
        """Generic header+rows Excel report."""
        filename = filename or self._default_filename(prefix)
        wb = Workbook()
        ws = wb.active
        ws.title = sheet_title
        self._write_header_row(ws, headers)
        for row_num, row in enumerate(rows, 2):
            for col_num, value in enumerate(row, 1):
                ws.cell(row=row_num, column=col_num, value=value)
            if row_styler:
                row_styler(ws, row_num, row)
        self._autosize_columns(ws)
        wb.save(filename)
        return filename

    @staticmethod
    def _fail_styler(ws, row_num: int, row: tuple) -> None:
        """Highlight the 4th column red when its value is 'Failed'."""
        if len(row) >= 4 and row[3] == "Failed":
            ws.cell(row=row_num, column=4).fill = _FAIL_FILL

    # =================================================================
    #  Reports
    # =================================================================
    def print_affected_policies_report(self, affected_policies: list[dict]) -> None:
        print(affected_policies)
        if not affected_policies:
            print("No policies found with rules containing problematic services.")
            return
        print("\n=== Affected Policies Report ===")
        print(f"Total affected policies: {len(affected_policies)}\n")
        for policy in affected_policies:
            print(f"Policy: {policy['policy_name']} (ID: {policy['policy_id']})")
            print(f"  Total affected rules: {len(policy['affected_rules'])}")
            for rule in policy["affected_rules"]:
                print(f"    - Rule: {rule['rule_name']} (ID: {rule['rule_id']})")
                print(f"      Problematic services: "
                      f"{', '.join(rule['problematic_services'])}")
            print()

    def generate_ips_application_report(self, affected_policies: list[dict],
                                        filename: Optional[str] = None) -> Optional[str]:
        if not affected_policies:
            print("No rules found with problematic services.")
            return None
        headers = [
            "ADOM", "Policy Package", "Rule ID", "Rule Name",
            "Source Addresses", "Destination Addresses", "Services",
            "Problematic Services", "Applicable IPS Profiles",
            "IPS Applied?", "Applied IPS Profile",
        ]
        rows = [
            (
                d["adom"], d["policy_package"], d["rule_id"], d["rule_name"],
                self._join(d["src"]), self._join(d["dst"]),
                self._join(d["rule_services"]),
                self._join(d["problematic_services"]),
                self._join(d["applicable_ips_profiles"]),
                d["ips_status"],
                self._join(d["applied_ips_profile"]),
            )
            for d in affected_policies
        ]
        filename = self._write_tabular_report(
            filename, "IPS Rules Report", "IPS_Rules_Report", headers, rows)
        print(f"IPS rules report generated successfully: {filename}")
        return filename

    def generate_ips_update_report(self, updated_rules: list[dict],
                                   filename: Optional[str] = None) -> Optional[str]:
        if not updated_rules:
            print("No rules were updated.")
            return None
        headers = ["Rule ID", "Rule Name", "IPS Sensor Applied", "Status",
                   "Error (if any)"]
        rows = [
            (r["rule_id"], r["rule_name"], self._join(r["ips_sensor_applied"]),
             r["status"], r.get("error", ""))
            for r in updated_rules
        ]
        filename = self._write_tabular_report(
            filename, "IPS Rules Update Report", "IPS_Rules_Update_Report",
            headers, rows, row_styler=self._fail_styler)
        print(f"IPS rules update report generated successfully: {filename}")
        return filename

    def generate_ips_removal_report(self, updated_rules: list[dict],
                                    filename: Optional[str] = None) -> Optional[str]:
        if not updated_rules:
            print("No se eliminaron perfiles IPS de reglas.")
            return None
        headers = ["Rule ID", "Rule Name", "IPS Sensor Removed", "Status",
                   "Error (if any)"]
        rows = [
            (r["rule_id"], r["rule_name"], self._join(r["ips_sensor_removed"]),
             r["status"], r.get("error", ""))
            for r in updated_rules
        ]
        filename = self._write_tabular_report(
            filename, "IPS Rules Removal Report", "IPS_Rules_Removal_Report",
            headers, rows, row_styler=self._fail_styler)
        print(f"Informe de eliminación de perfiles IPS generado exitosamente: "
              f"{filename}")
        return filename

    def generate_address_group_report(self, group_details: dict,
                                      filename: Optional[str] = None) -> Optional[str]:
        if not group_details:
            print("No address group details found.")
            return None
        filename = filename or self._default_filename("Address_Group_Report")
        wb = Workbook()
        ws = wb.active
        ws.title = "Address Group Details"
        self._write_header_row(ws, ["Property", "Value"])

        data = self._data(group_details, default={}) or {}
        rows = [
            ("Group Name", data.get("name", "N/A")),
            ("Comment", data.get("comment", "N/A")),
            ("Type", data.get("type", "N/A")),
        ]
        for row_num, (k, v) in enumerate(rows, 2):
            ws.cell(row=row_num, column=1, value=k)
            ws.cell(row=row_num, column=2, value=v)

        members = data.get("member") or []
        if members:
            row = len(rows) + 3
            ws.cell(row=row, column=1, value="Members")
            for member in members:
                row += 1
                ws.cell(row=row, column=2, value=member.get("name", "N/A"))

        self._autosize_columns(ws)
        wb.save(filename)
        print(f"Address group report generated successfully: {filename}")
        return filename

    def generate_ips_copy_report(self, results: dict,
                                 filename: Optional[str] = None) -> Optional[str]:
        if not results:
            print("No results to generate report")
            return None
        filename = filename or self._default_filename("IPS_Copy_Report")
        wb = Workbook()
        ws = wb.active
        ws.title = "IPS Copy Report"
        self._write_title_block(ws, "IPS Profile Copy Report")

        kv_pairs = [
            ("Source ADOM:", results.get("source_adom", "N/A")),
            ("Target ADOM:", results.get("target_adom", "N/A")),
            ("Target Version:", results.get("target_version", "N/A")),
            ("Date/Time:", results.get("timestamp", "N/A")),
        ]
        row = 4
        for k, v in kv_pairs:
            ws.cell(row=row, column=1, value=k)
            ws.cell(row=row, column=2, value=v)
            row += 1
        row += 1

        ws.cell(row=row, column=1, value="Results Summary").font = _HEADER_FONT
        row += 1
        summary = [
            ("Total profiles found", results.get("total_profiles", 0)),
            ("Profiles copied/updated",
             results.get("copied_profiles", 0) + results.get("updated_profiles", 0)),
            ("Profiles skipped", results.get("skipped_profiles", 0)),
            ("Profiles failed", results.get("failed_profiles", 0)),
        ]
        for label, value in summary:
            ws.cell(row=row, column=1, value=label)
            cell = ws.cell(row=row, column=2, value=value)
            if label == "Profiles failed" and value > 0:
                cell.fill = _FAIL_FILL
            row += 1
        row += 2

        ws.cell(row=row, column=1, value="Operation Details").font = _HEADER_FONT
        row += 1
        self._write_details_block(ws, row, results.get("details", []))

        self._autosize_columns(ws)
        wb.save(filename)
        print(f"IPS profile copy report generated successfully: {filename}")
        return filename

    def generate_policy_package_clone_report(self, results: dict,
                                             filename: Optional[str] = None) -> Optional[str]:
        if not results:
            print("No results to generate report")
            return None
        filename = filename or self._default_filename("Policy_Package_Clone_Report")
        wb = Workbook()
        ws = wb.active
        ws.title = "Policy Package Clone Report"
        self._write_title_block(ws, "Firewall Policy Package Clone Report")

        kv_pairs = [
            ("Source ADOM:", results.get("source_adom", "N/A")),
            ("Target ADOM:", results.get("target_adom", "N/A")),
            ("Source Package:", results.get("source_package", "N/A")),
            ("Target Package:", results.get("target_package", "N/A")),
        ]
        row = 4
        for k, v in kv_pairs:
            ws.cell(row=row, column=1, value=k)
            ws.cell(row=row, column=2, value=v)
            row += 1

        ws.cell(row=row, column=1, value="Status:")
        status_cell = ws.cell(row=row, column=2, value=results.get("status", "N/A"))
        if results.get("status") == "Success":
            status_cell.fill = _OK_FILL
        elif results.get("status") == "Failed":
            status_cell.fill = _FAIL_FILL
        row += 2

        ws.cell(row=row, column=1, value="Policy Statistics").font = _HEADER_FONT
        row += 1
        stats = [
            ("Total Policies", results.get("total_policies", 0)),
            ("Successfully Copied", results.get("copied_policies", 0)),
            ("Failed to Copy", results.get("failed_policies", 0)),
        ]
        for label, value in stats:
            ws.cell(row=row, column=1, value=label)
            cell = ws.cell(row=row, column=2, value=value)
            if label == "Failed to Copy" and value > 0:
                cell.fill = _FAIL_FILL
            row += 1
        row += 2

        ws.cell(row=row, column=1, value="Operation Details").font = _HEADER_FONT
        row += 1
        self._write_details_block(ws, row, results.get("details", []))

        self._autosize_columns(ws)
        wb.save(filename)
        print(f"Policy package clone report generated successfully: {filename}")
        return filename

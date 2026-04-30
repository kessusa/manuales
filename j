from __future__ import annotations

import traceback
from contextlib import contextmanager
from datetime import datetime

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

_IPS_FORBIDDEN_FIELDS = ("oid", "obj seq", "last-modified")
_IPS_7_0_ALLOWED_FIELDS = {
    "action", "application", "log", "status",
    "os", "protocol", "quarantine", "severity",
}


class FMNapi:
    """FortiManager JSON-RPC client."""

    def __init__(self, verify=False):
        self.base_url = FORTIMANAGER_HOST_URL
        self.username = FORTIMANAGER_USERNAME
        self.password = get_fortimanager_password()
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update({"Content-Type": "application/json"})
        self.session.proxies = {"https": None}

    def _request(self, method, endpoint, session_id=None, data=None, **extra):
        params = {"url": endpoint, **extra}
        if data is not None:
            params["data"] = data
        payload = {"id": 1, "method": method, "params": [params], "verbose": 1}
        if session_id is not None:
            payload["session"] = session_id
        return self.session.post(self.base_url, json=payload).json()

    @staticmethod
    def _data(response, default=None):
        if default is None:
            default = []
        return response.get("result", [{}])[0].get("data", default)

    @staticmethod
    def _status(response):
        return response.get("result", [{}])[0].get("status", {})

    @classmethod
    def _is_ok(cls, response):
        return cls._status(response).get("code") == 0

    @staticmethod
    def _is_drop_or_deny(action):
        return (action or "").lower() in ("drop", "deny")

    def login(self):
        return self._request(
            "exec", "/sys/login/user",
            data={"user": self.username, "passwd": self.password},
        )

    def logout(self, session_id):
        return self._request("exec", "/sys/logout", session_id)

    def workspace_action(self, session_id, adom, action):
        return self._request("exec", f"/dvmdb/adom/{adom}/workspace/{action}", session_id)

    @contextmanager
    def adom_workspace(self, session_id, adom, commit=True, verbose=True):
        lock = self.workspace_action(session_id, adom, "lock")
        if verbose:
            print(f"Lock ADOM ({adom}) response: {lock}")
        try:
            yield lock
            if commit:
                resp = self.workspace_action(session_id, adom, "commit")
                if verbose:
                    print(f"Commit ADOM ({adom}) response: {resp}")
        finally:
            resp = self.workspace_action(session_id, adom, "unlock")
            if verbose:
                print(f"Unlock ADOM ({adom}) response: {resp}")

    def get_adom_members(self, session_id):
        return self._request("get", "/dvmdb/adom", session_id, option="object member")

    def get_adom_names(self, session_id):
        return [item["name"] for item in self._data(self.get_adom_members(session_id))]

    def get_adom_list_info(self, session_id):
        result = []
        for item in self._data(self.get_adom_members(session_id)):
            adom_name = item["name"]
            for package in self._data(self.get_package_details(session_id, adom_name)):
                scope_members = package.get("scope member") or []
                if not scope_members:
                    continue
                expanded = []
                for member in scope_members:
                    if "ha" in member["name"].lower():
                        device = self._data(
                            self.get_device_details(session_id, member["name"]),
                            default={}) or {}
                        expanded.extend(
                            {"name": fw["name"], "vdom": member["vdom"]}
                            for fw in (device.get("ha_slave") or [])
                        )
                    else:
                        expanded.append(member)
                result.append({package["name"]: expanded})
        return result

    def get_devices(self, session_id):
        return self._request("get", "/dvmdb/device", session_id)

    def get_device_details(self, session_id, device):
        return self._request("get", f"/dvmdb/device/{device}", session_id)

    def list_firewalls(self, session_id, include_non_ha=False):
        names = []
        for item in self._data(self.get_devices(session_id)):
            ha_slaves = item.get("ha_slave")
            if ha_slaves:
                names.extend(fw["name"] for fw in ha_slaves)
            elif include_non_ha:
                names.extend(vdom["devid"] for vdom in item.get("vdom") or [])
        return names

    def get_ha_groups(self, session_id):
        groups = {}
        for device in self.list_firewalls(session_id):
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

    def get_package_details(self, session_id, adom):
        return self._request("get", f"/pm/pkg/adom/{adom}", session_id)

    def find_package(self, session_id, adom, package_name):
        """Search the entire ADOM folder tree and return paths where ``package_name`` exists."""
        found = []

        def walk(items, current_path):
            for item in items or []:
                name = item.get("name", "")
                obj_type = item.get("type", "")
                full_path = f"{current_path}/{name}" if current_path else name
                if name == package_name:
                    found.append({
                        "path": full_path,
                        "type": obj_type,
                        "scope_members": item.get("scope member", []),
                    })
                if obj_type == "folder" or item.get("subobj"):
                    walk(item.get("subobj") or [], full_path)

        walk(self._data(self.get_package_details(session_id, adom)), "")
        return found

    def get_all_policy_packages_in_adom(self, session_id, adom):
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

    def get_policy_package_details(self, session_id, adom, policy_package):
        return self._request(
            "get",
            f"/pm/config/adom/{adom}/pkg/{policy_package}/firewall/policy",
            session_id,
            fields=POLICY_FIELDS,
        )

    def get_policy_details(self, session_id, adom, policy_package, policy_id):
        return self._request(
            "get",
            f"/pm/config/adom/{adom}/pkg/{policy_package}/firewall/policy/{policy_id}",
            session_id,
        )

    def update_rule(self, session_id, adom, policy_package, rule_id,
                    update_data=None, ips_sensor=None):
        """Update a policy rule. If ``ips_sensor`` is given, applies UTM-enabling defaults."""
        data = dict(update_data) if update_data else {}
        if ips_sensor is not None:
            data.update({
                "ips-sensor": ips_sensor,
                "utm-status": "enable",
                "logtraffic": "utm",
                "logtraffic-start": "enable",
            })
        response = self._request(
            "update",
            f"/pm/config/adom/{adom}/pkg/{policy_package}/firewall/policy/{rule_id}",
            session_id,
            data=data,
        )
        if ips_sensor is not None:
            print(response)
        return response

    def get_service_group_details(self, session_id, adom, group_name):
        endpoints = (
            f"/pm/config/adom/{adom}/obj/firewall/service/group/{group_name}",
            f"/pm/config/adom/{adom}/obj/firewall/service/custom/{group_name}",
        )
        try:
            response = {}
            for endpoint in endpoints:
                response = self._request("get", endpoint, session_id)
                if response.get("result"):
                    return response
            return response
        except Exception as exc:
            print(f"Error getting service group details for {group_name}: {exc}")
            return None

    def get_address_group_details(self, session_id, adom, group_name):
        return self._request(
            "get",
            f"/pm/config/adom/{adom}/obj/firewall/addrgrp/{group_name}",
            session_id,
        )

    def update_address_group(self, session_id, adom, group_name, new_members):
        with self.adom_workspace(session_id, adom):
            return self._request(
                "update",
                f"/pm/config/adom/{adom}/obj/firewall/addrgrp/{group_name}",
                session_id,
                data={"member": new_members},
            )

    def get_script_details(self, session_id, adom):
        return self._request("get", "/dvmdb/script", session_id, data={"adom": adom})

    def execute_script(self, session_id, adom, policy_package, device, vdom, script):
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

    def get_rules_with_problematic_services(self, session_id, adom, policy_package,
                                            problematic_services, ips_profile_mapping):
        problematic = set(problematic_services)
        affected = []
        for policy in self._data(
                self.get_policy_package_details(session_id, adom, policy_package)):
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

    def _collect_problematic_services(self, session_id, adom, rule_services, problematic):
        found, expanded = [], []
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
            except Exception as exc:
                print(f"Error processing group {service}: {exc}")
        return found, expanded

    def manage_ips_on_rules(self, session_id, adom, policy_package, action,
                            problematic_services=None, ips_profile_mapping=None,
                            excluded_profiles=None):
        """Apply or remove IPS sensors on rules.

        action='apply':  needs ``problematic_services`` and ``ips_profile_mapping``.
        action='remove': optional ``excluded_profiles`` to keep specific sensors.
        """
        if action not in ("apply", "remove"):
            raise ValueError("action must be 'apply' or 'remove'")

        if action == "apply":
            iterable = self.get_rules_with_problematic_services(
                session_id, adom, policy_package,
                problematic_services or [], ips_profile_mapping or {})
        else:
            iterable = self._data(
                self.get_policy_package_details(session_id, adom, policy_package))

        excluded = set(excluded_profiles or [])
        results = []
        with self.adom_workspace(session_id, adom):
            for policy in iterable:
                result = self._process_ips_rule(
                    session_id, adom, policy_package, policy, action, excluded)
                if result is not None:
                    results.append(result)
        return results

    def _process_ips_rule(self, session_id, adom, policy_package, policy, action, excluded):
        if action == "apply":
            base = {"rule_id": policy["rule_id"], "rule_name": policy["rule_name"]}
            if self._is_drop_or_deny(policy.get("action")):
                return {**base, "ips_sensor_applied": "N/A (drop/deny action)",
                        "status": "Skipped"}
            if policy["ips_status"] != "No" or not policy["applicable_ips_profiles"]:
                return None
            profiles = policy["applicable_ips_profiles"]
            ips_sensor = "NETSEC_IPS_ALL_MONITOR" if len(profiles) > 1 else profiles[0]
            response = self.update_rule(
                session_id, adom, policy_package, policy["rule_id"],
                ips_sensor=ips_sensor)
            if self._is_ok(response):
                return {**base, "ips_sensor_applied": ips_sensor, "status": "Success"}
            return {**base, "ips_sensor_applied": ips_sensor, "status": "Failed",
                    "error": self._status(response).get("message")}

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

        update_data = {"ips-sensor": None, "utm-status": "disable"}
        for key in ("logtraffic", "logtraffic-start"):
            if policy.get(key):
                update_data[key] = policy[key]
        response = self.update_rule(session_id, adom, policy_package, rule_id,
                                    update_data=update_data)
        if self._is_ok(response):
            return {**base, "ips_sensor_removed": ips_profile, "status": "Success"}
        return {**base, "ips_sensor_removed": ips_profile, "status": "Failed",
                "error": self._status(response).get("message")}

    @staticmethod
    def _clean_entry(entry, target_version):
        for k in _IPS_FORBIDDEN_FIELDS:
            entry.pop(k, None)
        if target_version.startswith("7.0"):
            entry.pop("id", None)
            entry = {k: v for k, v in entry.items() if k in _IPS_7_0_ALLOWED_FIELDS}
        entry.setdefault("status", "enable")
        return entry

    @classmethod
    def _build_clean_data(cls, original, target_version):
        clean = {
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

    def copy_ips_profiles(self, session_id, source_adom, target_adom,
                          profile_names=None, copy_all=False,
                          target_version="7.2", overwrite_existing=False):
        if not profile_names and not copy_all:
            raise ValueError("Must specify profile_names or set copy_all=True")

        results = {
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
        except Exception as exc:
            log(f"\n✗ General error: {exc}")
            log(f"Error trace: {traceback.format_exc()}")

        print(results)
        return results

    def _copy_one_profile(self, session_id, source_adom, target_adom, profile,
                          target_names, target_version, overwrite_existing, results):
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
            clean = self._build_clean_data(details["result"][0]["data"], target_version)

            method = "update" if name in target_names else "add"
            endpoint = f"/pm/config/adom/{target_adom}/obj/ips/sensor"
            if method == "update":
                endpoint = f"{endpoint}/{name}"

            response = self._request(method, endpoint, session_id, data=clean)
            if self._is_ok(response):
                key = "copied_profiles" if method == "add" else "updated_profiles"
                results[key] += 1
                log(f"  ✓ Profile {method}d successfully: {name}")
            else:
                results["failed_profiles"] += 1
                log(f"  ✗ Error copying profile {name}: "
                    f"{self._status(response).get('message', 'Unknown error')}")
        except Exception as exc:
            results["failed_profiles"] += 1
            log(f"  ✗ Error processing profile {name}: {exc}")
            log(f"  Error trace: {traceback.format_exc()}")

    def clone_policy_package(self, session_id, source_adom, target_adom_folder,
                             source_package, target_package=None,
                             overwrite_existing=False, include_date_in_name=True,
                             wait_for_task=True, task_timeout=120):
        results = {
            "source_adom": source_adom,
            "target_folder": target_adom_folder,
            "source_package": source_package,
            "status": "Pending",
            "details": [],
            "timestamp": datetime.now().isoformat(),
        }
        log = results["details"].append
        try:
            target_package = self._build_clone_target_name(
                source_package, target_package, include_date_in_name)
            results["target_package"] = target_package
            log(f"Starting policy package clone operation from "
                f"{source_adom}/{source_package} to {source_adom}/{target_package}")

            # Normalise folder path: FortiManager rejects trailing slash on dst_parent.
            dst_parent = (target_adom_folder or "").rstrip("/")
            if not dst_parent:
                raise ValueError("target_adom_folder cannot be empty")

            with self.adom_workspace(session_id, source_adom):
                if not overwrite_existing:
                    log(f"Checking if target package exists: {target_package}")
                    existing = [
                        p["name"]
                        for p in self._data(self.get_package_details(session_id, source_adom))
                    ]
                    if target_package in existing:
                        raise RuntimeError(
                            f"Target package {target_package} already exists in "
                            f"{source_adom}. Set overwrite_existing=True to overwrite.")

                log(f"Attempting to clone package {source_package} -> {target_package}")
                log(f"Payload: adom={source_adom}, pkg={source_package}, "
                    f"dst_name={target_package}, dst_parent={dst_parent}")
                clone_response = self._request(
                    "exec", "/securityconsole/package/clone", session_id,
                    data={
                        "adom": source_adom,
                        "pkg": source_package,
                        "dst_name": target_package,
                        "dst_parent": dst_parent,
                    },
                )
                log(f"Clone package response: {clone_response}")

                if not self._is_ok(clone_response):
                    raise RuntimeError(
                        f"Failed to clone package: "
                        f"{self._status(clone_response).get('message', 'Unknown error')}")

                task_id = self._data(clone_response, default={}).get("task")
                if task_id and wait_for_task:
                    log(f"Clone is async (task_id={task_id}); waiting up to "
                        f"{task_timeout}s for completion...")
                    self._wait_for_task(session_id, task_id, task_timeout, log)

                log(f"Successfully cloned package {source_package} to {target_package}")

            new_pkg = self.get_policy_package_details(session_id, source_adom, target_package)
            results["total_policies"] = len(self._data(new_pkg))
            log(f"New package contains {results['total_policies']} policies")
            results["status"] = "Success"
        except Exception as exc:
            results["status"] = "Failed"
            log(f"Error during policy package clone: {exc}")
            log(f"Error trace: {traceback.format_exc()}")
        return results

    def _wait_for_task(self, session_id, task_id, timeout, log):
        """Poll /task/task/{id} until done or until ``timeout`` seconds pass."""
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            response = self._request("get", f"/task/task/{task_id}", session_id)
            data = self._data(response, default={}) or {}
            percent = data.get("percent", 0)
            state = data.get("state")
            num_err = data.get("num_err", 0)
            log(f"  Task {task_id}: state={state} percent={percent}% errors={num_err}")
            if percent == 100 or state in (4, "done"):
                if num_err:
                    raise RuntimeError(f"Task {task_id} finished with {num_err} errors: "
                                       f"{data.get('history', [])}")
                return data
            if state in (5, "error"):
                raise RuntimeError(f"Task {task_id} failed: {data}")
            time.sleep(2)
        raise TimeoutError(f"Task {task_id} did not finish within {timeout}s")

    @staticmethod
    def _build_clone_target_name(source_package, target_package, include_date_in_name):
        base_name = target_package or source_package
        if not include_date_in_name:
            return base_name
        current_date = datetime.now().strftime("%d-%m-%Y")
        if current_date in base_name:
            return base_name
        return f"{current_date}_{base_name}"

    @staticmethod
    def _default_filename(prefix):
        return f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

    @staticmethod
    def _join(value):
        if isinstance(value, (list, tuple, set)):
            return ", ".join(str(v) for v in value)
        return "" if value is None else str(value)

    @staticmethod
    def _write_header_row(ws, headers, row=1):
        for col_num, header in enumerate(headers, 1):
            cell = ws.cell(row=row, column=col_num, value=header)
            cell.font = _HEADER_FONT
            cell.alignment = _CENTER
            cell.fill = _HEADER_FILL

    @staticmethod
    def _autosize_columns(ws, max_width=100):
        for column in ws.columns:
            column_letter, max_length = None, 0
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
    def _write_title_block(ws, title, last_col="D"):
        ws.merge_cells(f"A1:{last_col}1")
        ws["A1"] = title
        ws["A1"].font = _TITLE_FONT
        ws["A1"].alignment = _CENTER
        ws.merge_cells(f"A2:{last_col}2")
        ws["A2"] = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        ws["A2"].alignment = _CENTER

    @staticmethod
    def _write_details_block(ws, start_row, details, max_width=100):
        row = start_row
        for detail in details:
            chunks = [detail[i:i + max_width] for i in range(0, len(detail), max_width)] \
                or [detail]
            for chunk in chunks:
                ws.cell(row=row, column=1, value=chunk)
                row += 1
        return row

    @staticmethod
    def _fail_styler(ws, row_num, row):
        if len(row) >= 4 and row[3] == "Failed":
            ws.cell(row=row_num, column=4).fill = _FAIL_FILL

    def _build_tabular_workbook(self, sheet_title, headers, rows, row_styler=None):
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
        return wb

    def print_affected_policies_report(self, affected_policies):
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

    def generate_ips_rules_report(self, kind, rows_data, filename=None):
        """Excel report for IPS rules. ``kind`` ∈ {'application','update','removal'}."""
        configs = {
            "application": {
                "title": "IPS Rules Report",
                "prefix": "IPS_Rules_Report",
                "empty_msg": "No rules found with problematic services.",
                "ok_msg": "IPS rules report generated successfully",
                "headers": [
                    "ADOM", "Policy Package", "Rule ID", "Rule Name",
                    "Source Addresses", "Destination Addresses", "Services",
                    "Problematic Services", "Applicable IPS Profiles",
                    "IPS Applied?", "Applied IPS Profile",
                ],
                "row_builder": lambda d: (
                    d["adom"], d["policy_package"], d["rule_id"], d["rule_name"],
                    self._join(d["src"]), self._join(d["dst"]),
                    self._join(d["rule_services"]),
                    self._join(d["problematic_services"]),
                    self._join(d["applicable_ips_profiles"]),
                    d["ips_status"], self._join(d["applied_ips_profile"]),
                ),
                "styler": None,
            },
            "update": {
                "title": "IPS Rules Update Report",
                "prefix": "IPS_Rules_Update_Report",
                "empty_msg": "No rules were updated.",
                "ok_msg": "IPS rules update report generated successfully",
                "headers": ["Rule ID", "Rule Name", "IPS Sensor Applied", "Status",
                            "Error (if any)"],
                "row_builder": lambda r: (
                    r["rule_id"], r["rule_name"], self._join(r["ips_sensor_applied"]),
                    r["status"], r.get("error", ""),
                ),
                "styler": self._fail_styler,
            },
            "removal": {
                "title": "IPS Rules Removal Report",
                "prefix": "IPS_Rules_Removal_Report",
                "empty_msg": "No se eliminaron perfiles IPS de reglas.",
                "ok_msg": "Informe de eliminación de perfiles IPS generado exitosamente",
                "headers": ["Rule ID", "Rule Name", "IPS Sensor Removed", "Status",
                            "Error (if any)"],
                "row_builder": lambda r: (
                    r["rule_id"], r["rule_name"], self._join(r["ips_sensor_removed"]),
                    r["status"], r.get("error", ""),
                ),
                "styler": self._fail_styler,
            },
        }
        if kind not in configs:
            raise ValueError(f"kind must be one of {list(configs)}")
        cfg = configs[kind]

        if not rows_data:
            print(cfg["empty_msg"])
            return None

        filename = filename or self._default_filename(cfg["prefix"])
        rows = [cfg["row_builder"](r) for r in rows_data]
        wb = self._build_tabular_workbook(
            cfg["title"], cfg["headers"], rows, cfg["styler"])
        wb.save(filename)
        print(f"{cfg['ok_msg']}: {filename}")
        return filename

    def generate_address_group_report(self, group_details, filename=None):
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

    def generate_summary_report(self, kind, results, filename=None):
        """Title + KV pairs + stats + details. ``kind`` ∈ {'ips_copy','package_clone'}."""
        configs = {
            "ips_copy": {
                "title": "IPS Profile Copy Report",
                "prefix": "IPS_Copy_Report",
                "sheet": "IPS Copy Report",
                "ok_msg": "IPS profile copy report generated successfully",
                "kv_pairs": [
                    ("Source ADOM:", "source_adom"),
                    ("Target ADOM:", "target_adom"),
                    ("Target Version:", "target_version"),
                    ("Date/Time:", "timestamp"),
                ],
                "status_key": None,
                "stats_title": "Results Summary",
                "stats": [
                    ("Total profiles found", lambda r: r.get("total_profiles", 0)),
                    ("Profiles copied/updated",
                     lambda r: r.get("copied_profiles", 0) + r.get("updated_profiles", 0)),
                    ("Profiles skipped", lambda r: r.get("skipped_profiles", 0)),
                    ("Profiles failed", lambda r: r.get("failed_profiles", 0)),
                ],
                "fail_label": "Profiles failed",
            },
            "package_clone": {
                "title": "Firewall Policy Package Clone Report",
                "prefix": "Policy_Package_Clone_Report",
                "sheet": "Policy Package Clone Report",
                "ok_msg": "Policy package clone report generated successfully",
                "kv_pairs": [
                    ("Source ADOM:", "source_adom"),
                    ("Target ADOM:", "target_adom"),
                    ("Source Package:", "source_package"),
                    ("Target Package:", "target_package"),
                ],
                "status_key": "status",
                "stats_title": "Policy Statistics",
                "stats": [
                    ("Total Policies", lambda r: r.get("total_policies", 0)),
                    ("Successfully Copied", lambda r: r.get("copied_policies", 0)),
                    ("Failed to Copy", lambda r: r.get("failed_policies", 0)),
                ],
                "fail_label": "Failed to Copy",
            },
        }
        if kind not in configs:
            raise ValueError(f"kind must be one of {list(configs)}")
        cfg = configs[kind]

        if not results:
            print("No results to generate report")
            return None

        filename = filename or self._default_filename(cfg["prefix"])
        wb = Workbook()
        ws = wb.active
        ws.title = cfg["sheet"]
        self._write_title_block(ws, cfg["title"])

        row = 4
        for label, key in cfg["kv_pairs"]:
            ws.cell(row=row, column=1, value=label)
            ws.cell(row=row, column=2, value=results.get(key, "N/A"))
            row += 1

        if cfg["status_key"]:
            ws.cell(row=row, column=1, value="Status:")
            cell = ws.cell(row=row, column=2, value=results.get(cfg["status_key"], "N/A"))
            if cell.value == "Success":
                cell.fill = _OK_FILL
            elif cell.value == "Failed":
                cell.fill = _FAIL_FILL
            row += 1
        row += 1

        ws.cell(row=row, column=1, value=cfg["stats_title"]).font = _HEADER_FONT
        row += 1
        for label, getter in cfg["stats"]:
            ws.cell(row=row, column=1, value=label)
            value = getter(results)
            cell = ws.cell(row=row, column=2, value=value)
            if label == cfg["fail_label"] and value > 0:
                cell.fill = _FAIL_FILL
            row += 1
        row += 2

        ws.cell(row=row, column=1, value="Operation Details").font = _HEADER_FONT
        row += 1
        self._write_details_block(ws, row, results.get("details", []))

        self._autosize_columns(ws)
        wb.save(filename)
        print(f"{cfg['ok_msg']}: {filename}")
        return filename


# ============================================================================
# Test runner — adjust ADOM and POLICY_PACKAGE before running
# ============================================================================
ADOM = "your-adom"
POLICY_PACKAGE = "your-policy-package"
BACKUP_FOLDER = "backups/"
EXCLUDED_PROFILES = []

# Inline configuration (for self-contained testing).
_GROUPS = {
    "NETSEC_IPS_DnsLdapKerberos_MONITOR": [
        "TCP_53", "TCP_389", "TCP_636", "TCP_88",
        "LDAP", "LDAP_UDP", "DNS", "KERBEROS",
    ],
    "NETSEC_IPS_FTP_MONITOR": ["TCP_20", "TCP_21", "FTP", "FTP_GET", "FTP_PUT"],
    "NETSEC_IPS_HTTP-S_MONITOR": ["TCP_80", "TCP_443", "HTTP", "HTTPS"],
    "NETSEC_IPS_MSSQL_MONITOR": ["TCP_1433", "TCP_14330", "UDP_1434", "MS-SQL"],
    "NETSEC_IPS_MySQL_MONITOR": ["TCP_3306", "TCP_6606", "MYSQL"],
    "NETSEC_IPS_NETBIOS_MONITOR": ["TCP_137", "TCP_138", "TCP_139", "SAMBA"],
    "NETSEC_IPS_ORACLE_MONITOR": [
        "TCP_1521", "TCP_1522", "TCP_1523", "TCP_1524",
        "TCP_1525", "TCP_1526", "TCP_1521-1526",
    ],
    "NETSEC_IPS_PostgreSQL_MONITOR": ["TCP_5432"],
    "NETSEC_IPS_RDP_MONITOR": ["TCP_3389", "RDP"],
    "NETSEC_IPS_RPC_MONITOR": ["TCP_135", "DCE-RPC", "RPC"],
    "NETSEC_IPS_SMB_MONITOR": ["TCP_445", "SMB"],
    "NETSEC_IPS_SSH-SFTP_MONITOR": ["TCP_22", "TCP_2222", "SSH"],
    "NETSEC_IPS_VNC_MONITOR": ["TCP_5900", "TCP_5901", "VNC"],
    "NETSEC_IPS_ALL_MONITOR": ["NS-PVR_SVC_INFRA-DC", "FORBIDDEN_PROTOCOLS"],
}
IPS_PROFILE_MAPPING = {
    service: [profile]
    for profile, services in _GROUPS.items()
    for service in services
}
PROBLEMATIC_SERVICES = list(IPS_PROFILE_MAPPING)


def main():
    api = FMNapi()
    session_id = None

    try:
        login_response = api.login()
        session_id = login_response["session"]
        print(f"Login successful (session: {session_id})")

        print("\n=== Step 1: Cloning Policy Package ===")
        clone_results = api.clone_policy_package(
            session_id,
            source_adom=ADOM,
            target_adom_folder=BACKUP_FOLDER,
            source_package=POLICY_PACKAGE,
            include_date_in_name=True,
        )
        clone_report = api.generate_summary_report("package_clone", clone_results)
        print(f"Clone operation completed. Report generated: {clone_report}")

        print("\n=== Step 2: Removing Existing IPS Profiles ===")
        print(f"\nRemoving IPS profiles from package {POLICY_PACKAGE}...")
        removed_rules = api.manage_ips_on_rules(
            session_id, ADOM, POLICY_PACKAGE,
            action="remove", excluded_profiles=EXCLUDED_PROFILES,
        )
        ips_removal_report = api.generate_ips_rules_report("removal", removed_rules)
        print(f"\nIPS removal operation completed. "
              f"Report generated: {ips_removal_report}")

        print("\n=== Step 3: Applying New IPS Profiles ===")
        print(f"\nApplying new IPS profiles to package {POLICY_PACKAGE}...")

        print("\nGenerating report of affected rules...")
        affected_rules = api.get_rules_with_problematic_services(
            session_id, ADOM, POLICY_PACKAGE,
            PROBLEMATIC_SERVICES, IPS_PROFILE_MAPPING,
        )
        affected_rules_report = api.generate_ips_rules_report("application", affected_rules)
        print(f"Affected rules report generated: {affected_rules_report}")

        print("\nApplying IPS profiles to affected rules...")
        updated_rules = api.manage_ips_on_rules(
            session_id, ADOM, POLICY_PACKAGE,
            action="apply",
            problematic_services=PROBLEMATIC_SERVICES,
            ips_profile_mapping=IPS_PROFILE_MAPPING,
        )
        ips_update_report = api.generate_ips_rules_report("update", updated_rules)
        print(f"IPS application report generated: {ips_update_report}")

        print("\n=== All operations completed successfully ===")

    except Exception as exc:
        print(f"\nError during operations: {exc}")
        print(f"Error trace: {traceback.format_exc()}")
    finally:
        if session_id:
            print("\nLogging out...")
            logout_response = api.logout(session_id)
            print(f"Logout response: {logout_response}")


if __name__ == "__main__":
    main()

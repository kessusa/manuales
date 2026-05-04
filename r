from __future__ import annotations

import time
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

    @contextmanager
    def adom_workspace(self, session_id, adom, commit=True):
        lock = self._request("exec", f"/dvmdb/adom/{adom}/workspace/lock", session_id)
        print(f"Lock ADOM ({adom}): {lock}")
        try:
            yield lock
            if commit:
                resp = self._request(
                    "exec", f"/dvmdb/adom/{adom}/workspace/commit", session_id)
                print(f"Commit ADOM ({adom}): {resp}")
        finally:
            resp = self._request(
                "exec", f"/dvmdb/adom/{adom}/workspace/unlock", session_id)
            print(f"Unlock ADOM ({adom}): {resp}")

    def login(self):
        return self._request(
            "exec", "/sys/login/user",
            data={"user": self.username, "passwd": self.password},
        )

    def logout(self, session_id):
        return self._request("exec", "/sys/logout", session_id)

    def find_package(self, session_id, adom, package_name):
        """Walk the ADOM folder tree and return paths where ``package_name`` exists."""
        found = []
        response = self._request("get", f"/pm/pkg/adom/{adom}", session_id)
        items = response.get("result", [{}])[0].get("data", [])

        def walk(nodes, current_path):
            for item in nodes or []:
                name = item.get("name", "")
                full_path = f"{current_path}/{name}" if current_path else name
                if name == package_name:
                    found.append({"path": full_path, "type": item.get("type", "")})
                if item.get("subobj") or item.get("type") == "folder":
                    walk(item.get("subobj") or [], full_path)

        walk(items, "")
        return found

    def get_rules_with_problematic_services(self, session_id, adom, policy_package,
                                            problematic_services, ips_profile_mapping):
        problematic = set(problematic_services)
        response = self._request(
            "get",
            f"/pm/config/adom/{adom}/pkg/{policy_package}/firewall/policy",
            session_id, fields=POLICY_FIELDS,
        )
        affected = []
        for policy in response.get("result", [{}])[0].get("data", []):
            if (policy.get("action") or "").lower() in ("drop", "deny"):
                continue

            rule_services = policy.get("service") or []
            problematic_in_rule, expanded = [], []

            for service in rule_services:
                if service in problematic:
                    problematic_in_rule.append(service)
                    continue
                try:
                    group = self._request(
                        "get",
                        f"/pm/config/adom/{adom}/obj/firewall/service/group/{service}",
                        session_id)
                    if not group.get("result"):
                        group = self._request(
                            "get",
                            f"/pm/config/adom/{adom}/obj/firewall/service/custom/{service}",
                            session_id)
                    group_data = (group.get("result") or [{}])[0].get("data") or {}
                    if not isinstance(group_data, dict):
                        continue
                    for member in group_data.get("member") or []:
                        if member in problematic:
                            problematic_in_rule.append(member)
                            expanded.append(f"{service} -> {member}")
                except Exception as exc:
                    print(f"Error processing group {service}: {exc}")

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

    def manage_ips_on_rules(self, session_id, adom, policy_package, action,
                            problematic_services=None, ips_profile_mapping=None,
                            excluded_profiles=None):
        """action='apply' or 'remove'."""
        if action == "apply":
            iterable = self.get_rules_with_problematic_services(
                session_id, adom, policy_package,
                problematic_services or [], ips_profile_mapping or {})
        elif action == "remove":
            response = self._request(
                "get",
                f"/pm/config/adom/{adom}/pkg/{policy_package}/firewall/policy",
                session_id, fields=POLICY_FIELDS,
            )
            iterable = response.get("result", [{}])[0].get("data", [])
        else:
            raise ValueError("action must be 'apply' or 'remove'")

        excluded = set(excluded_profiles or [])
        results = []

        with self.adom_workspace(session_id, adom):
            for policy in iterable:
                if action == "apply":
                    base = {"rule_id": policy["rule_id"], "rule_name": policy["rule_name"]}
                    if (policy.get("action") or "").lower() in ("drop", "deny"):
                        results.append({**base,
                                        "ips_sensor_applied": "N/A (drop/deny action)",
                                        "status": "Skipped"})
                        continue
                    if policy["ips_status"] != "No" or not policy["applicable_ips_profiles"]:
                        continue
                    profiles = policy["applicable_ips_profiles"]
                    sensor = "NETSEC_IPS_ALL_MONITOR" if len(profiles) > 1 else profiles[0]
                    update_data = {
                        "ips-sensor": sensor,
                        "utm-status": "enable",
                        "logtraffic": "utm",
                        "logtraffic-start": "enable",
                    }
                    response = self._request(
                        "update",
                        f"/pm/config/adom/{adom}/pkg/{policy_package}"
                        f"/firewall/policy/{policy['rule_id']}",
                        session_id, data=update_data,
                    )
                    status = response.get("result", [{}])[0].get("status", {})
                    if status.get("code") == 0:
                        results.append({**base, "ips_sensor_applied": sensor,
                                        "status": "Success"})
                    else:
                        results.append({**base, "ips_sensor_applied": sensor,
                                        "status": "Failed",
                                        "error": status.get("message")})
                    continue

                rule_id = policy.get("policyid", "")
                rule_name = policy.get("name", "N/A")
                ips_profile = policy.get("ips-sensor")
                if isinstance(ips_profile, list) and ips_profile:
                    ips_profile = ips_profile[0]
                base = {"rule_id": rule_id, "rule_name": rule_name}

                if (policy.get("action") or "").lower() in ("drop", "deny"):
                    results.append({**base,
                                    "ips_sensor_removed": "N/A (drop/deny action)",
                                    "status": "Skipped"})
                    continue
                if not ips_profile:
                    continue
                if "block" in str(ips_profile).lower():
                    print(f"Not removing {ips_profile}")
                    results.append({**base,
                                    "ips_sensor_removed":
                                        "N/A (excluded profile is already a blocking profile)",
                                    "status": "Skipped",
                                    "current_ips_sensor": ips_profile})
                    continue
                if ips_profile in excluded:
                    results.append({**base,
                                    "ips_sensor_removed": "N/A (excluded profile)",
                                    "status": "Skipped",
                                    "current_ips_sensor": ips_profile})
                    continue

                update_data = {"ips-sensor": None, "utm-status": "disable"}
                for key in ("logtraffic", "logtraffic-start"):
                    if policy.get(key):
                        update_data[key] = policy[key]
                response = self._request(
                    "update",
                    f"/pm/config/adom/{adom}/pkg/{policy_package}"
                    f"/firewall/policy/{rule_id}",
                    session_id, data=update_data,
                )
                status = response.get("result", [{}])[0].get("status", {})
                if status.get("code") == 0:
                    results.append({**base, "ips_sensor_removed": ips_profile,
                                    "status": "Success"})
                else:
                    results.append({**base, "ips_sensor_removed": ips_profile,
                                    "status": "Failed",
                                    "error": status.get("message")})

        return results

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
            base_name = target_package or source_package
            if include_date_in_name:
                current_date = datetime.now().strftime("%d-%m-%Y")
                if current_date not in base_name:
                    base_name = f"{current_date}_{base_name}"
            target_package = base_name
            results["target_package"] = target_package
            log(f"Starting clone: {source_adom}/{source_package} -> "
                f"{source_adom}/{target_package}")

            dst_parent = (target_adom_folder or "").rstrip("/")
            if not dst_parent:
                raise ValueError("target_adom_folder cannot be empty")

            with self.adom_workspace(session_id, source_adom):
                if not overwrite_existing:
                    existing_response = self._request(
                        "get", f"/pm/pkg/adom/{source_adom}", session_id)
                    existing = [
                        p["name"]
                        for p in existing_response.get("result", [{}])[0].get("data", [])
                    ]
                    if target_package in existing:
                        raise RuntimeError(
                            f"Target package {target_package} already exists in "
                            f"{source_adom}. Set overwrite_existing=True to overwrite.")

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
                log(f"Clone response: {clone_response}")
                status = clone_response.get("result", [{}])[0].get("status", {})
                if status.get("code") != 0:
                    raise RuntimeError(
                        f"Failed to clone package: "
                        f"{status.get('message', 'Unknown error')}")

                task_data = clone_response.get("result", [{}])[0].get("data") or {}
                task_id = task_data.get("task") if isinstance(task_data, dict) else None
                if task_id and wait_for_task:
                    log(f"Waiting up to {task_timeout}s for task {task_id}...")
                    deadline = time.monotonic() + task_timeout
                    while time.monotonic() < deadline:
                        task_resp = self._request(
                            "get", f"/task/task/{task_id}", session_id)
                        task = task_resp.get("result", [{}])[0].get("data") or {}
                        percent = task.get("percent", 0)
                        state = task.get("state")
                        num_err = task.get("num_err", 0)
                        log(f"  task {task_id}: state={state} percent={percent}% "
                            f"errors={num_err}")
                        if percent == 100 or state in (4, "done"):
                            if num_err:
                                raise RuntimeError(
                                    f"Task {task_id} finished with {num_err} errors: "
                                    f"{task.get('history', [])}")
                            break
                        if state in (5, "error"):
                            raise RuntimeError(f"Task {task_id} failed: {task}")
                        time.sleep(2)
                    else:
                        raise TimeoutError(
                            f"Task {task_id} did not finish within {task_timeout}s")

                log(f"Successfully cloned {source_package} to {target_package}")

            new_pkg = self._request(
                "get",
                f"/pm/config/adom/{source_adom}/pkg/{target_package}/firewall/policy",
                session_id, fields=POLICY_FIELDS,
            )
            results["total_policies"] = len(
                new_pkg.get("result", [{}])[0].get("data", []))
            log(f"New package contains {results['total_policies']} policies")
            results["status"] = "Success"
        except Exception as exc:
            results["status"] = "Failed"
            log(f"Error during policy package clone: {exc}")
            log(f"Error trace: {traceback.format_exc()}")
        return results

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
                source_response = self._request(
                    "get", f"/pm/config/adom/{source_adom}/obj/ips/sensor", session_id)
                source_profiles = source_response.get("result", [{}])[0].get("data", [])
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

                target_response = self._request(
                    "get", f"/pm/config/adom/{target_adom}/obj/ips/sensor", session_id)
                target_names = {
                    p["name"]
                    for p in target_response.get("result", [{}])[0].get("data", [])
                }
                log(f"Existing profiles in target: {len(target_names)}")

                for profile in profiles_to_copy:
                    name = profile["name"]
                    log(f"\nProcessing profile: {name}")
                    try:
                        if name in target_names and not overwrite_existing:
                            results["skipped_profiles"] += 1
                            log(f"  Profile {name} already exists - skipping")
                            continue

                        details_response = self._request(
                            "get",
                            f"/pm/config/adom/{source_adom}/obj/ips/sensor/{name}",
                            session_id)
                        if not details_response.get("result"):
                            raise RuntimeError(f"Could not get details for {name}")
                        original = details_response["result"][0]["data"]

                        clean_entries = []
                        for entry in original.get("entries", []):
                            entry = entry.copy()
                            for k in _IPS_FORBIDDEN_FIELDS:
                                entry.pop(k, None)
                            if target_version.startswith("7.0"):
                                entry.pop("id", None)
                                entry = {k: v for k, v in entry.items()
                                         if k in _IPS_7_0_ALLOWED_FIELDS}
                            entry.setdefault("status", "enable")
                            clean_entries.append(entry)

                        clean = {
                            "name": original["name"],
                            "comment": original.get("comment", ""),
                            "entries": clean_entries,
                            "extended-log": original.get("extended-log", "disable"),
                        }
                        if target_version.startswith("7.2"):
                            clean["block-malicious-url"] = original.get(
                                "block-malicious-url", "disable")
                            clean["scan-botnet-connections"] = original.get(
                                "scan-botnet-connections", "disable")
                        if original.get("replacemsg-group"):
                            clean["replacemsg-group"] = original["replacemsg-group"]

                        method = "update" if name in target_names else "add"
                        endpoint = f"/pm/config/adom/{target_adom}/obj/ips/sensor"
                        if method == "update":
                            endpoint = f"{endpoint}/{name}"
                        response = self._request(method, endpoint, session_id, data=clean)
                        status = response.get("result", [{}])[0].get("status", {})

                        if status.get("code") == 0:
                            key = "copied_profiles" if method == "add" else "updated_profiles"
                            results[key] += 1
                            log(f"  ✓ Profile {method}d: {name}")
                        else:
                            results["failed_profiles"] += 1
                            log(f"  ✗ Error: {status.get('message', 'Unknown error')}")
                    except Exception as exc:
                        results["failed_profiles"] += 1
                        log(f"  ✗ Error processing {name}: {exc}")
                        log(f"  Trace: {traceback.format_exc()}")
        except Exception as exc:
            log(f"\n✗ General error: {exc}")
            log(f"Error trace: {traceback.format_exc()}")

        print(results)
        return results

    def generate_ips_rules_report(self, kind, rows_data, filename=None):
        """kind ∈ {'application','update','removal'}."""
        configs = {
            "application": (
                "IPS Rules Report", "IPS_Rules_Report",
                "No rules found with problematic services.",
                ["ADOM", "Policy Package", "Rule ID", "Rule Name",
                 "Source Addresses", "Destination Addresses", "Services",
                 "Problematic Services", "Applicable IPS Profiles",
                 "IPS Applied?", "Applied IPS Profile"],
                lambda d: (
                    d["adom"], d["policy_package"], d["rule_id"], d["rule_name"],
                    _join(d["src"]), _join(d["dst"]), _join(d["rule_services"]),
                    _join(d["problematic_services"]),
                    _join(d["applicable_ips_profiles"]),
                    d["ips_status"], _join(d["applied_ips_profile"]),
                ),
                False,
            ),
            "update": (
                "IPS Rules Update Report", "IPS_Rules_Update_Report",
                "No rules were updated.",
                ["Rule ID", "Rule Name", "IPS Sensor Applied", "Status",
                 "Error (if any)"],
                lambda r: (r["rule_id"], r["rule_name"],
                           _join(r["ips_sensor_applied"]),
                           r["status"], r.get("error", "")),
                True,
            ),
            "removal": (
                "IPS Rules Removal Report", "IPS_Rules_Removal_Report",
                "No se eliminaron perfiles IPS de reglas.",
                ["Rule ID", "Rule Name", "IPS Sensor Removed", "Status",
                 "Error (if any)"],
                lambda r: (r["rule_id"], r["rule_name"],
                           _join(r["ips_sensor_removed"]),
                           r["status"], r.get("error", "")),
                True,
            ),
        }
        if kind not in configs:
            raise ValueError(f"kind must be one of {list(configs)}")
        title, prefix, empty_msg, headers, row_builder, mark_failures = configs[kind]

        if not rows_data:
            print(empty_msg)
            return None

        filename = filename or f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        wb = Workbook()
        ws = wb.active
        ws.title = title

        for col_num, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col_num, value=header)
            cell.font = _HEADER_FONT
            cell.alignment = _CENTER
            cell.fill = _HEADER_FILL

        for row_num, row_data in enumerate(rows_data, 2):
            row = row_builder(row_data)
            for col_num, value in enumerate(row, 1):
                ws.cell(row=row_num, column=col_num, value=value)
            if mark_failures and len(row) >= 4 and row[3] == "Failed":
                ws.cell(row=row_num, column=4).fill = _FAIL_FILL

        _autosize(ws)
        wb.save(filename)
        print(f"{title} saved: {filename}")
        return filename

    def generate_summary_report(self, kind, results, filename=None):
        """kind ∈ {'ips_copy','package_clone'}."""
        configs = {
            "ips_copy": (
                "IPS Profile Copy Report", "IPS_Copy_Report",
                [("Source ADOM:", "source_adom"),
                 ("Target ADOM:", "target_adom"),
                 ("Target Version:", "target_version"),
                 ("Date/Time:", "timestamp")],
                None, "Results Summary",
                [("Total profiles found", lambda r: r.get("total_profiles", 0)),
                 ("Profiles copied/updated",
                  lambda r: r.get("copied_profiles", 0) + r.get("updated_profiles", 0)),
                 ("Profiles skipped", lambda r: r.get("skipped_profiles", 0)),
                 ("Profiles failed", lambda r: r.get("failed_profiles", 0))],
                "Profiles failed",
            ),
            "package_clone": (
                "Firewall Policy Package Clone Report", "Policy_Package_Clone_Report",
                [("Source ADOM:", "source_adom"),
                 ("Target ADOM:", "target_adom"),
                 ("Source Package:", "source_package"),
                 ("Target Package:", "target_package")],
                "status", "Policy Statistics",
                [("Total Policies", lambda r: r.get("total_policies", 0)),
                 ("Successfully Copied", lambda r: r.get("copied_policies", 0)),
                 ("Failed to Copy", lambda r: r.get("failed_policies", 0))],
                "Failed to Copy",
            ),
        }
        if kind not in configs:
            raise ValueError(f"kind must be one of {list(configs)}")
        title, prefix, kv_pairs, status_key, stats_title, stats, fail_label = configs[kind]

        if not results:
            print("No results to generate report")
            return None

        filename = filename or f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        wb = Workbook()
        ws = wb.active
        ws.title = title[:31]

        ws.merge_cells("A1:D1")
        ws["A1"] = title
        ws["A1"].font = _TITLE_FONT
        ws["A1"].alignment = _CENTER
        ws.merge_cells("A2:D2")
        ws["A2"] = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        ws["A2"].alignment = _CENTER

        row = 4
        for label, key in kv_pairs:
            ws.cell(row=row, column=1, value=label)
            ws.cell(row=row, column=2, value=results.get(key, "N/A"))
            row += 1

        if status_key:
            ws.cell(row=row, column=1, value="Status:")
            cell = ws.cell(row=row, column=2, value=results.get(status_key, "N/A"))
            if cell.value == "Success":
                cell.fill = _OK_FILL
            elif cell.value == "Failed":
                cell.fill = _FAIL_FILL
            row += 1
        row += 1

        ws.cell(row=row, column=1, value=stats_title).font = _HEADER_FONT
        row += 1
        for label, getter in stats:
            ws.cell(row=row, column=1, value=label)
            value = getter(results)
            cell = ws.cell(row=row, column=2, value=value)
            if label == fail_label and value > 0:
                cell.fill = _FAIL_FILL
            row += 1
        row += 2

        ws.cell(row=row, column=1, value="Operation Details").font = _HEADER_FONT
        row += 1
        for detail in results.get("details", []):
            chunks = [detail[i:i + 100] for i in range(0, len(detail), 100)] or [detail]
            for chunk in chunks:
                ws.cell(row=row, column=1, value=chunk)
                row += 1

        _autosize(ws)
        wb.save(filename)
        print(f"{title} saved: {filename}")
        return filename


def _join(value):
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(v) for v in value)
    return "" if value is None else str(value)


def _autosize(ws, max_width=100):
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


# ============================================================================
# Test runner
# ============================================================================
ADOM = "your-adom"
POLICY_PACKAGE = "your-policy-package"
BACKUP_FOLDER = "backups"
EXCLUDED_PROFILES = []

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
        print(f"Clone report: {clone_report}")

        print("\n=== Step 2: Removing Existing IPS Profiles ===")
        removed_rules = api.manage_ips_on_rules(
            session_id, ADOM, POLICY_PACKAGE,
            action="remove", excluded_profiles=EXCLUDED_PROFILES,
        )
        ips_removal_report = api.generate_ips_rules_report("removal", removed_rules)
        print(f"Removal report: {ips_removal_report}")

        print("\n=== Step 3: Applying New IPS Profiles ===")
        affected_rules = api.get_rules_with_problematic_services(
            session_id, ADOM, POLICY_PACKAGE,
            PROBLEMATIC_SERVICES, IPS_PROFILE_MAPPING,
        )
        affected_rules_report = api.generate_ips_rules_report("application", affected_rules)
        print(f"Affected rules report: {affected_rules_report}")

        updated_rules = api.manage_ips_on_rules(
            session_id, ADOM, POLICY_PACKAGE,
            action="apply",
            problematic_services=PROBLEMATIC_SERVICES,
            ips_profile_mapping=IPS_PROFILE_MAPPING,
        )
        ips_update_report = api.generate_ips_rules_report("update", updated_rules)
        print(f"Application report: {ips_update_report}")

        print("\n=== All operations completed successfully ===")

    except Exception as exc:
        print(f"\nError: {exc}")
        print(f"Trace: {traceback.format_exc()}")
    finally:
        if session_id:
            print("\nLogging out...")
            print(f"Logout: {api.logout(session_id)}")


if __name__ == "__main__":
    main()

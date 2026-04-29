"""Configuration: services considered problematic and their IPS-profile mapping.

Centralised here so it can be tweaked without touching ``fortimanager.py`` or
the playflows that use it.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Profile names (single source of truth — change here once)
# ---------------------------------------------------------------------------
_DNS_LDAP_KRB = "NETSEC_IPS_DnsLdapKerberos_MONITOR"
_FTP = "NETSEC_IPS_FTP_MONITOR"
_HTTP = "NETSEC_IPS_HTTP-S_MONITOR"
_MSSQL = "NETSEC_IPS_MSSQL_MONITOR"
_MYSQL = "NETSEC_IPS_MySQL_MONITOR"
_NETBIOS = "NETSEC_IPS_NETBIOS_MONITOR"
_ORACLE = "NETSEC_IPS_ORACLE_MONITOR"
_POSTGRES = "NETSEC_IPS_PostgreSQL_MONITOR"
_RDP = "NETSEC_IPS_RDP_MONITOR"
_RPC = "NETSEC_IPS_RPC_MONITOR"
_SMB = "NETSEC_IPS_SMB_MONITOR"
_SSH_SFTP = "NETSEC_IPS_SSH-SFTP_MONITOR"
_VNC = "NETSEC_IPS_VNC_MONITOR"
_ALL = "NETSEC_IPS_ALL_MONITOR"

# ---------------------------------------------------------------------------
# service-name -> [profile, ...]
# Each block keeps services together for readability.
# ---------------------------------------------------------------------------
_GROUPS: dict[str, list[str]] = {
    _DNS_LDAP_KRB: [
        "TCP_53", "TCP_389", "TCP_636", "TCP_88",
        "LDAP", "LDAP_UDP", "DNS", "KERBEROS",
    ],
    _FTP: ["TCP_20", "TCP_21", "FTP", "FTP_GET", "FTP_PUT"],
    _HTTP: ["TCP_80", "TCP_443", "HTTP", "HTTPS"],
    _MSSQL: ["TCP_1433", "TCP_14330", "UDP_1434", "MS-SQL"],
    _MYSQL: ["TCP_3306", "TCP_6606", "MYSQL"],
    _NETBIOS: ["TCP_137", "TCP_138", "TCP_139", "SAMBA"],
    _ORACLE: [
        "TCP_1521", "TCP_1522", "TCP_1523", "TCP_1524",
        "TCP_1525", "TCP_1526", "TCP_1521-1526",
    ],
    _POSTGRES: ["TCP_5432"],
    _RDP: ["TCP_3389", "RDP"],
    _RPC: ["TCP_135", "DCE-RPC", "RPC"],
    _SMB: ["TCP_445", "SMB"],
    _SSH_SFTP: ["TCP_22", "TCP_2222", "SSH"],
    _VNC: ["TCP_5900", "TCP_5901", "VNC"],
    _ALL: ["NS-PVR_SVC_INFRA-DC", "FORBIDDEN_PROTOCOLS"],
}

# Flat: every problematic service mapped to its applicable profile(s).
IPS_PROFILE_MAPPING: dict[str, list[str]] = {
    service: [profile]
    for profile, services in _GROUPS.items()
    for service in services
}

# Flat list of problematic service names (the keys above, in stable order).
PROBLEMATIC_SERVICES: list[str] = list(IPS_PROFILE_MAPPING)

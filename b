"""Smoke test para todos los métodos públicos de AVIIWAFApi."""

from avi_iwaf_api import AVIIWAFApi


if __name__ == "__main__":
    avi_waf = AVIIWAFApi(env='emea')

    tenant = "EMEA-PRODUCTION-SECURITY"
    policy_name = "SIGNATURE-ENFORCEMENT-TEST"

    # Datos de ejemplo
    pre_crs_group = "REACT_SERVER_VULN"
    pre_crs_rule_name = "block_react_eval"
    pre_crs_rule_str = 'SecRule REQUEST_URI "@contains /eval" "id:1001,phase:1,deny,status:403"'

    crs_group = "CRS_903_9002_Wordpress_Exclusion_Rules"
    crs_rule_id = "9002140"

    exclusion_uri = {"uri_path": "/admin/mologo"}
    exclusion_ip = {
        "client_subnet": {"ip_addr": {"addr": "10.0.0.5", "type": "V4"}, "mask": 32}
    }

    def section(title):
        print(f"\n{'=' * 60}\n{title}\n{'=' * 60}")

    # ------------------------------------------------------------------ #
    # GET DATA
    # ------------------------------------------------------------------ #
    section("get_data")
    data = avi_waf.get_data()
    print(f"Retrieved {len(data)} virtual services.")

    # ------------------------------------------------------------------ #
    # GROUP OPERATIONS - pre_crs
    # ------------------------------------------------------------------ #
    section("PRE_CRS GROUP OPERATIONS")

    # enable_group también crea el grupo si no existe (sólo pre_crs)
    avi_waf.enable_group(tenant, policy_name, pre_crs_group, group_type="pre_crs")
    avi_waf.disable_group(tenant, policy_name, pre_crs_group, group_type="pre_crs")
    avi_waf.enable_group(tenant, policy_name, pre_crs_group, group_type="pre_crs")

    # ------------------------------------------------------------------ #
    # RULE OPERATIONS - pre_crs
    # ------------------------------------------------------------------ #
    section("PRE_CRS RULE OPERATIONS")

    # enable_rule crea la regla si no existe (sólo pre_crs)
    avi_waf.enable_rule(
        tenant, policy_name, pre_crs_group,
        rule_name=pre_crs_rule_name, group_type="pre_crs"
    )
    avi_waf.disable_rule(
        tenant, policy_name, pre_crs_group,
        rule_name=pre_crs_rule_name, group_type="pre_crs"
    )
    avi_waf.enable_rule(
        tenant, policy_name, pre_crs_group,
        rule_name=pre_crs_rule_name, group_type="pre_crs"
    )

    # ------------------------------------------------------------------ #
    # EXCLUSION OPERATIONS - pre_crs
    # ------------------------------------------------------------------ #
    section("PRE_CRS EXCLUSION OPERATIONS")

    avi_waf.add_group_exclusion(
        tenant, policy_name, pre_crs_group, exclusion_uri, group_type="pre_crs"
    )
    avi_waf.add_group_exclusion(
        tenant, policy_name, pre_crs_group, exclusion_ip, group_type="pre_crs"
    )
    avi_waf.delete_group_exclusion(
        tenant, policy_name, pre_crs_group,
        exclusion_id=f"uri_{exclusion_uri['uri_path']}", group_type="pre_crs"
    )

    # ------------------------------------------------------------------ #
    # GROUP OPERATIONS - crs
    # ------------------------------------------------------------------ #
    section("CRS GROUP OPERATIONS")

    avi_waf.disable_group(tenant, policy_name, crs_group, group_type="crs")
    avi_waf.enable_group(tenant, policy_name, crs_group, group_type="crs")

    # ------------------------------------------------------------------ #
    # RULE OPERATIONS - crs
    # ------------------------------------------------------------------ #
    section("CRS RULE OPERATIONS")

    avi_waf.disable_rule(
        tenant, policy_name, crs_group,
        rule_id=crs_rule_id, group_type="crs"
    )
    avi_waf.enable_rule(
        tenant, policy_name, crs_group,
        rule_id=crs_rule_id, group_type="crs"
    )
    avi_waf.modify_rule_mode(
        tenant, policy_name, crs_group, crs_rule_id,
        new_mode="WAF_MODE_DETECTION_ONLY", group_type="crs"
    )
    avi_waf.modify_rule_mode(
        tenant, policy_name, crs_group, crs_rule_id,
        new_mode="WAF_MODE_ENFORCEMENT", group_type="crs"
    )

    # ------------------------------------------------------------------ #
    # EXCLUSION OPERATIONS - crs
    # ------------------------------------------------------------------ #
    section("CRS EXCLUSION OPERATIONS")

    # Group-level
    avi_waf.add_group_exclusion(
        tenant, policy_name, crs_group, exclusion_uri, group_type="crs"
    )
    avi_waf.delete_group_exclusion(
        tenant, policy_name, crs_group,
        exclusion_id=f"uri_{exclusion_uri['uri_path']}", group_type="crs"
    )

    # Rule-level (sólo crs)
    avi_waf.add_rule_exclusion(
        tenant, policy_name, crs_group, crs_rule_id, exclusion_uri, group_type="crs"
    )
    avi_waf.delete_rule_exclusion(
        tenant, policy_name, crs_group, crs_rule_id,
        exclusion_id=f"uri_{exclusion_uri['uri_path']}", group_type="crs"
    )

    # Validación: rule_exclusion en pre_crs debe fallar con mensaje claro
    avi_waf.delete_rule_exclusion(
        tenant, policy_name, pre_crs_group, crs_rule_id,
        exclusion_id="rule_9002140", group_type="pre_crs"
    )

    # ------------------------------------------------------------------ #
    # CLEANUP - delete pre_crs rule and group
    # ------------------------------------------------------------------ #
    section("CLEANUP")

    avi_waf.delete_rule(
        tenant, policy_name, pre_crs_group,
        rule_name=pre_crs_rule_name, group_type="pre_crs"
    )
    avi_waf.delete_group(tenant, policy_name, pre_crs_group, group_type="pre_crs")

    print("\nAll tests finished.")

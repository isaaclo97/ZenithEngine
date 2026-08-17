from engine.parser import parse_workflow

# Imports kept explicit (no wildcard) so it's clear where each rule comes from.

from engine.rules.triggers import (
    check_pull_request_target_1000,
    check_checkout_without_ref_1001,
    check_pull_request_without_branch_restriction_1013,
    check_expression_injection_1016,
    check_toctou_pattern_1021,
    check_always_true_condition_1022
)

from engine.rules.permissions import (
    check_missing_permissions_1003,
    check_third_party_action_with_token_1011
)

from engine.rules.actions import (
    check_action_without_hash_1002,
    check_unverified_action_1007,
    check_action_not_in_marketplace_1008,
    check_branch_as_version_1012,
    check_latest_as_version_1017,
    check_outdated_action_runtime_1023
)

from engine.rules.credentials import (
    check_hardcoded_credential_1014,
    check_secret_in_logs_1019
)

from engine.rules.network import (
    check_egress_policy_1004,
    check_fraudulent_domain_1005,
    check_direct_ip_call_1009,
    check_dns_exfiltration_1015,
    check_github_api_exfiltration_1018
)

from engine.rules.runners import (
    check_runs_on_self_hosted_1006,
    check_runner_ec2_without_hardening_1020,
    check_unknown_runner_label_1024
)

from engine.rules.artifacts import (
    check_missing_artifact_verification_1010
)

from engine.rules.vulnerabilities import (
    check_known_vulnerable_component_1025
)

SEVERITY_ORDER = {
    'CRITICAL': 0,
    'HIGH': 1,
    'MEDIUM': 2,
    'LOW': 3
}

RULES = [
    check_pull_request_target_1000,
    check_checkout_without_ref_1001,
    check_action_without_hash_1002,
    check_missing_permissions_1003,
    check_egress_policy_1004,
    check_fraudulent_domain_1005,
    check_runs_on_self_hosted_1006,
    check_unverified_action_1007,
    check_action_not_in_marketplace_1008,
    check_direct_ip_call_1009,
    check_missing_artifact_verification_1010,
    check_third_party_action_with_token_1011,
    check_branch_as_version_1012,
    check_pull_request_without_branch_restriction_1013,
    check_hardcoded_credential_1014,
    check_dns_exfiltration_1015,
    check_expression_injection_1016,
    check_latest_as_version_1017,
    check_github_api_exfiltration_1018,
    check_secret_in_logs_1019,
    check_runner_ec2_without_hardening_1020,
    check_toctou_pattern_1021,
    check_always_true_condition_1022,
    check_outdated_action_runtime_1023,
    check_unknown_runner_label_1024,
    check_known_vulnerable_component_1025
]

def analyze_workflow(file_path, lang='es'):
    workflow, lines = parse_workflow(file_path)

    alerts = []
    for rule in RULES:
        try:
            result = rule(workflow, lines, lang)
            alerts.extend(result)
        except Exception as e:
            print(f'Error running rule {rule.__name__}: {e}')

    # Deduplicate alerts that are the same rule, same line, AND same
    # rendered text. Keying on (rule_id, line) alone silently drops
    # genuinely distinct findings whenever find_line's naive substring
    # search happens to resolve two different findings to the same line
    # number (e.g. two different unpinned actions on lines that both
    # contain a shared substring) — description makes the key precise
    # enough to only collapse true duplicates.
    seen = set()
    unique_alerts = []
    for alert in alerts:
        key = (alert['rule_id'], alert['line'], alert['description'])
        if key not in seen:
            seen.add(key)
            unique_alerts.append(alert)

    unique_alerts.sort(key=lambda a: SEVERITY_ORDER.get(a['severity'], 99))

    return unique_alerts

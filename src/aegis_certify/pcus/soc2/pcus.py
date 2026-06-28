"""
AEGIS Certify — SOC 2 Type II PCU Implementations

Implements PCUs for SOC 2 Trust Services Criteria following the canonical 7-step pipeline:
  1. Fix the predicate (no drift)
  2. Identify observable variables
  3. Define evidence interfaces
  4. Define thresholds explicitly
  5. Implement deterministic logic
  6. Emit structured result
  7. Bind to predicate(s)

Reference: AICPA Trust Services Criteria (2017)
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import TYPE_CHECKING, Any

from aegis_certify.core.models import (
    Artifact,
    Context,
    EvidenceBundle,
    EvidenceSpec,
    PCUResult,
    PCUType,
)
from aegis_certify.core.pcu import BasePCU

if TYPE_CHECKING:
    from aegis_certify.pcus.registry import PCURegistry


# ═══════════════════════════════════════════════════════════════════════════════
# CC6 — LOGICAL AND PHYSICAL ACCESS CONTROLS
# ═══════════════════════════════════════════════════════════════════════════════


class SOC2CC61LogicalAccessPCU(BasePCU):
    """PCU-SOC2-CC6.1 — Logical Access Security

    Predicate P-SOC2-CC6.1:
      The entity implements logical access security software, infrastructure,
      and architectures over protected information assets to protect them from
      security events to meet the entity's objectives.

    Observable Variables:
      - access_control_system_deployed: bool
      - rbac_enabled: bool
      - access_policies_documented: bool
      - access_logs_enabled: bool
    """

    pcu_id = "PCU-SOC2-CC6-1"
    version = "1.0.0"
    evaluates = ["P-SOC2-CC6.1"]
    framework = "soc2"
    description = "Validates logical access security controls are implemented"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="access_control_config",
            source="iam_system",
            type="access_control",
            required=True,
        ),
        EvidenceSpec(
            name="access_policies",
            source="policy_repo",
            type="policy_document",
            required=True,
        ),
        EvidenceSpec(
            name="access_logs_config",
            source="logging_system",
            type="logging_config",
            required=False,
        ),
    ]

    parameters = {
        "require_rbac": True,
        "require_mfa_for_privileged": True,
        "max_days_since_policy_review": 365,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        access_config = self.get_evidence(evidence, "access_control")
        policies = self.get_evidence(evidence, "policy_document")

        if access_config is None:
            return self.warn("Missing access control configuration evidence")

        if policies is None:
            return self.warn("Missing access policy documentation")

        evidence_refs = [
            access_config.hash or access_config.evidence_id,
            policies.hash or policies.evidence_id,
        ]

        config_data = access_config.data
        policy_data = policies.data

        # Check access control system deployment
        if not config_data.get("access_control_enabled", False):
            return self.fail(
                "Access control system not enabled",
                measurements={"access_control_enabled": False},
                evidence_refs=evidence_refs,
            )

        # Check RBAC if required
        if self.parameters["require_rbac"]:
            if not config_data.get("rbac_enabled", False):
                return self.fail(
                    "RBAC not enabled (required by policy)",
                    measurements={"rbac_enabled": False},
                    evidence_refs=evidence_refs,
                )

        # Check MFA for privileged accounts
        if self.parameters["require_mfa_for_privileged"]:
            mfa_privileged = config_data.get("mfa_privileged_accounts", False)
            if not mfa_privileged:
                return self.fail(
                    "MFA not enabled for privileged accounts",
                    measurements={"mfa_privileged": False},
                    evidence_refs=evidence_refs,
                )

        # Check policy review date
        last_review = policy_data.get("last_review_date")
        if last_review:
            try:
                review_date = datetime.fromisoformat(last_review)
                days_since = (datetime.now(timezone.utc) - review_date).days
                if days_since > self.parameters["max_days_since_policy_review"]:
                    return self.fail(
                        f"Access policy not reviewed in {days_since} days "
                        f"(max: {self.parameters['max_days_since_policy_review']})",
                        measurements={"days_since_policy_review": days_since},
                        evidence_refs=evidence_refs,
                    )
            except (ValueError, TypeError):
                pass  # Non-blocking if date parsing fails

        return self.pass_result(
            measurements={
                "access_control_enabled": True,
                "rbac_enabled": config_data.get("rbac_enabled", False),
                "mfa_privileged": config_data.get("mfa_privileged_accounts", False),
            },
            evidence_refs=evidence_refs,
        )


class SOC2CC62CredentialManagementPCU(BasePCU):
    """PCU-SOC2-CC6.2 — Credential Management

    Predicate P-SOC2-CC6.2:
      Prior to issuing system credentials and granting system access, the entity
      registers and authorizes new internal and external users whose access is
      administered by the entity.
    """

    pcu_id = "PCU-SOC2-CC6-2"
    version = "1.0.0"
    evaluates = ["P-SOC2-CC6.2"]
    framework = "soc2"
    description = "Validates credential management and user provisioning"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="provisioning_records",
            source="iam_system",
            type="user_provisioning",
            required=True,
        ),
        EvidenceSpec(
            name="approval_records",
            source="ticketing_system",
            type="access_approvals",
            required=True,
        ),
    ]

    parameters = {
        "require_manager_approval": True,
        "max_provisioning_without_approval_pct": 0.0,  # Zero tolerance
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        provisioning = self.get_evidence(evidence, "user_provisioning")
        approvals = self.get_evidence(evidence, "access_approvals")

        if provisioning is None:
            return self.warn("Missing user provisioning records")

        if approvals is None:
            return self.warn("Missing access approval records")

        evidence_refs = [
            provisioning.hash or provisioning.evidence_id,
            approvals.hash or approvals.evidence_id,
        ]

        prov_data = provisioning.data
        approval_data = approvals.data

        total_provisions = prov_data.get("total_provisions", 0)
        approved_provisions = approval_data.get("approved_count", 0)

        if total_provisions == 0:
            return self.warn("No provisioning records found")

        unapproved = total_provisions - approved_provisions
        unapproved_pct = (unapproved / total_provisions) * 100 if total_provisions > 0 else 0

        if unapproved_pct > self.parameters["max_provisioning_without_approval_pct"]:
            return self.fail(
                f"{unapproved} of {total_provisions} provisions lack approval "
                f"({unapproved_pct:.1f}%)",
                measurements={
                    "total_provisions": total_provisions,
                    "approved_provisions": approved_provisions,
                    "unapproved_pct": unapproved_pct,
                },
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "total_provisions": total_provisions,
                "approved_provisions": approved_provisions,
                "approval_rate": 100.0,
            },
            evidence_refs=evidence_refs,
        )


class SOC2CC63AccessRemovalPCU(BasePCU):
    """PCU-SOC2-CC6.3 — Access Removal

    Predicate P-SOC2-CC6.3:
      The entity removes access to protected information assets when system
      access is no longer needed (e.g., upon termination or role change).
    """

    pcu_id = "PCU-SOC2-CC6-3"
    version = "1.0.0"
    evaluates = ["P-SOC2-CC6.3"]
    framework = "soc2"
    description = "Validates timely access removal upon termination/role change"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="termination_records",
            source="hr_system",
            type="employee_terminations",
            required=True,
        ),
        EvidenceSpec(
            name="access_removal_logs",
            source="iam_system",
            type="access_deprovisioning",
            required=True,
        ),
    ]

    parameters = {
        "max_hours_to_remove_access": 24,  # Access must be removed within 24 hours
        "max_late_removal_pct": 5.0,  # Allow 5% grace for edge cases
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        terminations = self.get_evidence(evidence, "employee_terminations")
        removals = self.get_evidence(evidence, "access_deprovisioning")

        if terminations is None:
            return self.warn("Missing termination records")

        if removals is None:
            return self.warn("Missing access removal logs")

        evidence_refs = [
            terminations.hash or terminations.evidence_id,
            removals.hash or removals.evidence_id,
        ]

        term_data = terminations.data
        removal_data = removals.data

        total_terminations = term_data.get("total_terminations", 0)
        timely_removals = removal_data.get("timely_removals", 0)
        late_removals = removal_data.get("late_removals", 0)
        avg_removal_hours = removal_data.get("avg_removal_hours", 0)

        if total_terminations == 0:
            return self.pass_result(
                measurements={"total_terminations": 0, "note": "No terminations in period"},
                evidence_refs=evidence_refs,
            )

        late_pct = (late_removals / total_terminations) * 100 if total_terminations > 0 else 0

        if late_pct > self.parameters["max_late_removal_pct"]:
            return self.fail(
                f"{late_removals} late access removals ({late_pct:.1f}%) exceeds "
                f"threshold ({self.parameters['max_late_removal_pct']}%)",
                measurements={
                    "total_terminations": total_terminations,
                    "timely_removals": timely_removals,
                    "late_removals": late_removals,
                    "late_pct": late_pct,
                    "avg_removal_hours": avg_removal_hours,
                },
                evidence_refs=evidence_refs,
            )

        if avg_removal_hours > self.parameters["max_hours_to_remove_access"]:
            return self.fail(
                f"Average access removal time {avg_removal_hours:.1f}h exceeds "
                f"threshold {self.parameters['max_hours_to_remove_access']}h",
                measurements={
                    "avg_removal_hours": avg_removal_hours,
                    "threshold_hours": self.parameters["max_hours_to_remove_access"],
                },
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "total_terminations": total_terminations,
                "timely_removals": timely_removals,
                "avg_removal_hours": avg_removal_hours,
            },
            evidence_refs=evidence_refs,
        )


class SOC2CC64AccessReviewPCU(BasePCU):
    """PCU-SOC2-CC6.4 — Access Review

    Predicate P-SOC2-CC6.4:
      The entity reviews access rights periodically and removes access that
      is no longer required.
    """

    pcu_id = "PCU-SOC2-CC6-4"
    version = "1.0.0"
    evaluates = ["P-SOC2-CC6.4"]
    framework = "soc2"
    description = "Validates periodic access review process"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="access_review_records",
            source="iam_system",
            type="access_reviews",
            required=True,
        ),
    ]

    parameters = {
        "max_days_between_reviews": 90,  # Quarterly reviews
        "min_review_completion_pct": 95.0,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        reviews = self.get_evidence(evidence, "access_reviews")

        if reviews is None:
            return self.warn("Missing access review records")

        evidence_refs = [reviews.hash or reviews.evidence_id]
        review_data = reviews.data

        last_review_date = review_data.get("last_review_date")
        accounts_reviewed = review_data.get("accounts_reviewed", 0)
        total_accounts = review_data.get("total_accounts", 0)
        access_removed = review_data.get("access_removed", 0)

        # Check review recency
        if last_review_date:
            try:
                review_date = datetime.fromisoformat(last_review_date)
                days_since = (datetime.now(timezone.utc) - review_date).days
                if days_since > self.parameters["max_days_between_reviews"]:
                    return self.fail(
                        f"Last access review was {days_since} days ago "
                        f"(max: {self.parameters['max_days_between_reviews']})",
                        measurements={"days_since_last_review": days_since},
                        evidence_refs=evidence_refs,
                    )
            except (ValueError, TypeError):
                return self.warn("Invalid last review date format")
        else:
            return self.fail(
                "No access review date found",
                measurements={},
                evidence_refs=evidence_refs,
            )

        # Check review completion
        if total_accounts > 0:
            completion_pct = (accounts_reviewed / total_accounts) * 100
            if completion_pct < self.parameters["min_review_completion_pct"]:
                return self.fail(
                    f"Access review completion {completion_pct:.1f}% below "
                    f"threshold {self.parameters['min_review_completion_pct']}%",
                    measurements={
                        "accounts_reviewed": accounts_reviewed,
                        "total_accounts": total_accounts,
                        "completion_pct": completion_pct,
                    },
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "last_review_date": last_review_date,
                "accounts_reviewed": accounts_reviewed,
                "total_accounts": total_accounts,
                "access_removed": access_removed,
            },
            evidence_refs=evidence_refs,
        )


class SOC2CC65PhysicalAccessPCU(BasePCU):
    """PCU-SOC2-CC6.5 — Physical Access

    Predicate P-SOC2-CC6.5:
      The entity restricts physical access to facilities and protected
      information assets to authorized personnel.
    """

    pcu_id = "PCU-SOC2-CC6-5"
    version = "1.0.0"
    evaluates = ["P-SOC2-CC6.5"]
    framework = "soc2"
    description = "Validates physical access controls"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="physical_access_logs",
            source="badge_system",
            type="badge_access_logs",
            required=True,
        ),
        EvidenceSpec(
            name="visitor_logs",
            source="reception_system",
            type="visitor_records",
            required=False,
        ),
    ]

    parameters = {
        "require_badge_access": True,
        "max_unauthorized_access_events": 0,
        "require_visitor_escort": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        badge_logs = self.get_evidence(evidence, "badge_access_logs")

        if badge_logs is None:
            return self.warn("Missing physical access logs")

        evidence_refs = [badge_logs.hash or badge_logs.evidence_id]
        badge_data = badge_logs.data

        badge_system_active = badge_data.get("badge_system_active", False)
        unauthorized_events = badge_data.get("unauthorized_access_events", 0)
        tailgating_events = badge_data.get("tailgating_events", 0)

        if self.parameters["require_badge_access"] and not badge_system_active:
            return self.fail(
                "Badge access system not active",
                measurements={"badge_system_active": False},
                evidence_refs=evidence_refs,
            )

        total_violations = unauthorized_events + tailgating_events
        if total_violations > self.parameters["max_unauthorized_access_events"]:
            return self.fail(
                f"{total_violations} physical access violations detected "
                f"(unauthorized: {unauthorized_events}, tailgating: {tailgating_events})",
                measurements={
                    "unauthorized_events": unauthorized_events,
                    "tailgating_events": tailgating_events,
                },
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "badge_system_active": True,
                "unauthorized_events": unauthorized_events,
                "tailgating_events": tailgating_events,
            },
            evidence_refs=evidence_refs,
        )


class SOC2CC66ExternalThreatsPCU(BasePCU):
    """PCU-SOC2-CC6.6 — External Threats Protection

    Predicate P-SOC2-CC6.6:
      The entity implements logical access security measures to protect
      against threats from sources outside its system boundaries.
    """

    pcu_id = "PCU-SOC2-CC6-6"
    version = "1.0.0"
    evaluates = ["P-SOC2-CC6.6"]
    framework = "soc2"
    description = "Validates protection against external threats"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="firewall_config",
            source="network_security",
            type="firewall_configuration",
            required=True,
        ),
        EvidenceSpec(
            name="ids_alerts",
            source="security_monitoring",
            type="ids_ips_alerts",
            required=True,
        ),
        EvidenceSpec(
            name="vuln_scan",
            source="vulnerability_scanner",
            type="vulnerability_scan",
            required=False,
        ),
    ]

    parameters = {
        "require_firewall": True,
        "require_ids_ips": True,
        "max_critical_vulns": 0,
        "max_high_vulns": 5,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        firewall = self.get_evidence(evidence, "firewall_configuration")
        ids = self.get_evidence(evidence, "ids_ips_alerts")
        vuln_scan = self.get_evidence(evidence, "vulnerability_scan")

        if firewall is None:
            return self.warn("Missing firewall configuration evidence")

        if ids is None:
            return self.warn("Missing IDS/IPS evidence")

        evidence_refs = [
            firewall.hash or firewall.evidence_id,
            ids.hash or ids.evidence_id,
        ]

        fw_data = firewall.data
        ids_data = ids.data

        # Check firewall
        if self.parameters["require_firewall"]:
            if not fw_data.get("firewall_enabled", False):
                return self.fail(
                    "Firewall not enabled",
                    measurements={"firewall_enabled": False},
                    evidence_refs=evidence_refs,
                )

            default_deny = fw_data.get("default_deny_inbound", False)
            if not default_deny:
                return self.fail(
                    "Firewall does not have default-deny inbound policy",
                    measurements={"default_deny_inbound": False},
                    evidence_refs=evidence_refs,
                )

        # Check IDS/IPS
        if self.parameters["require_ids_ips"]:
            if not ids_data.get("ids_enabled", False):
                return self.fail(
                    "IDS/IPS not enabled",
                    measurements={"ids_enabled": False},
                    evidence_refs=evidence_refs,
                )

        measurements: dict[str, Any] = {
            "firewall_enabled": fw_data.get("firewall_enabled"),
            "default_deny_inbound": fw_data.get("default_deny_inbound"),
            "ids_enabled": ids_data.get("ids_enabled"),
        }

        # Check vulnerabilities if scan available
        if vuln_scan:
            evidence_refs.append(vuln_scan.hash or vuln_scan.evidence_id)
            vuln_data = vuln_scan.data
            critical = vuln_data.get("critical_count", 0)
            high = vuln_data.get("high_count", 0)

            measurements["critical_vulns"] = critical
            measurements["high_vulns"] = high

            if critical > self.parameters["max_critical_vulns"]:
                return self.fail(
                    f"{critical} critical vulnerabilities found (max: {self.parameters['max_critical_vulns']})",
                    measurements=measurements,
                    evidence_refs=evidence_refs,
                )

            if high > self.parameters["max_high_vulns"]:
                return self.fail(
                    f"{high} high vulnerabilities found (max: {self.parameters['max_high_vulns']})",
                    measurements=measurements,
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(measurements=measurements, evidence_refs=evidence_refs)


class SOC2CC67TransmissionProtectionPCU(BasePCU):
    """PCU-SOC2-CC6.7 — Transmission Protection

    Predicate P-SOC2-CC6.7:
      The entity restricts the transmission, movement, and removal of
      information to authorized internal and external users and processes,
      and protects it during transmission.
    """

    pcu_id = "PCU-SOC2-CC6-7"
    version = "1.0.0"
    evaluates = ["P-SOC2-CC6.7"]
    framework = "soc2"
    description = "Validates data transmission protection"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="tls_config",
            source="network_security",
            type="tls_configuration",
            required=True,
        ),
        EvidenceSpec(
            name="certificate_inventory",
            source="certificate_manager",
            type="ssl_certificates",
            required=False,
        ),
    ]

    parameters = {
        "min_tls_version": "1.2",
        "require_hsts": True,
        "max_days_to_cert_expiry_warn": 30,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        tls_config = self.get_evidence(evidence, "tls_configuration")

        if tls_config is None:
            return self.warn("Missing TLS configuration evidence")

        evidence_refs = [tls_config.hash or tls_config.evidence_id]
        tls_data = tls_config.data

        tls_enabled = tls_data.get("tls_enabled", False)
        min_version = tls_data.get("min_tls_version", "")
        hsts_enabled = tls_data.get("hsts_enabled", False)

        if not tls_enabled:
            return self.fail(
                "TLS not enabled for transmission",
                measurements={"tls_enabled": False},
                evidence_refs=evidence_refs,
            )

        # Check TLS version
        version_map = {"1.0": 1.0, "1.1": 1.1, "1.2": 1.2, "1.3": 1.3}
        min_required = version_map.get(self.parameters["min_tls_version"], 1.2)
        actual_version = version_map.get(min_version, 0)

        if actual_version < min_required:
            return self.fail(
                f"TLS version {min_version} below minimum required "
                f"{self.parameters['min_tls_version']}",
                measurements={"min_tls_version": min_version},
                evidence_refs=evidence_refs,
            )

        if self.parameters["require_hsts"] and not hsts_enabled:
            return self.fail(
                "HSTS not enabled",
                measurements={"hsts_enabled": False},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "tls_enabled": True,
                "min_tls_version": min_version,
                "hsts_enabled": hsts_enabled,
            },
            evidence_refs=evidence_refs,
        )


class SOC2CC68MalwareProtectionPCU(BasePCU):
    """PCU-SOC2-CC6.8 — Malware Protection

    Predicate P-SOC2-CC6.8:
      The entity implements controls to prevent or detect and act upon
      the introduction of unauthorized or malicious software.
    """

    pcu_id = "PCU-SOC2-CC6-8"
    version = "1.0.0"
    evaluates = ["P-SOC2-CC6.8"]
    framework = "soc2"
    description = "Validates malware protection controls"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="antimalware_status",
            source="endpoint_security",
            type="antimalware_deployment",
            required=True,
        ),
        EvidenceSpec(
            name="edr_alerts",
            source="edr_platform",
            type="edr_alerts",
            required=False,
        ),
    ]

    parameters = {
        "min_deployment_coverage_pct": 98.0,
        "max_days_since_definition_update": 3,
        "require_real_time_scanning": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        av_status = self.get_evidence(evidence, "antimalware_deployment")

        if av_status is None:
            return self.warn("Missing antimalware deployment evidence")

        evidence_refs = [av_status.hash or av_status.evidence_id]
        av_data = av_status.data

        deployed_count = av_data.get("deployed_endpoints", 0)
        total_endpoints = av_data.get("total_endpoints", 0)
        real_time_enabled = av_data.get("real_time_scanning_enabled", False)
        days_since_update = av_data.get("days_since_definition_update", 999)

        if total_endpoints == 0:
            return self.warn("No endpoint data available")

        coverage_pct = (deployed_count / total_endpoints) * 100

        if coverage_pct < self.parameters["min_deployment_coverage_pct"]:
            return self.fail(
                f"Antimalware coverage {coverage_pct:.1f}% below threshold "
                f"{self.parameters['min_deployment_coverage_pct']}%",
                measurements={
                    "deployed_endpoints": deployed_count,
                    "total_endpoints": total_endpoints,
                    "coverage_pct": coverage_pct,
                },
                evidence_refs=evidence_refs,
            )

        if self.parameters["require_real_time_scanning"] and not real_time_enabled:
            return self.fail(
                "Real-time malware scanning not enabled",
                measurements={"real_time_scanning_enabled": False},
                evidence_refs=evidence_refs,
            )

        if days_since_update > self.parameters["max_days_since_definition_update"]:
            return self.fail(
                f"Malware definitions {days_since_update} days old "
                f"(max: {self.parameters['max_days_since_definition_update']})",
                measurements={"days_since_definition_update": days_since_update},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "coverage_pct": coverage_pct,
                "real_time_scanning_enabled": real_time_enabled,
                "days_since_definition_update": days_since_update,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# CC7 — SYSTEM OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════════


class SOC2CC71VulnerabilityDetectionPCU(BasePCU):
    """PCU-SOC2-CC7.1 — Vulnerability Detection

    Predicate P-SOC2-CC7.1:
      The entity uses detection and monitoring procedures to identify
      changes to system configurations and potential vulnerabilities.
    """

    pcu_id = "PCU-SOC2-CC7-1"
    version = "1.0.0"
    evaluates = ["P-SOC2-CC7.1"]
    framework = "soc2"
    description = "Validates vulnerability detection procedures"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="vuln_scan_results",
            source="vulnerability_scanner",
            type="vulnerability_scan",
            required=True,
        ),
        EvidenceSpec(
            name="scan_schedule",
            source="vulnerability_scanner",
            type="scan_schedule",
            required=False,
        ),
    ]

    parameters = {
        "max_days_since_scan": 30,
        "max_critical_unpatched": 0,
        "max_high_unpatched_days": 30,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        vuln_scan = self.get_evidence(evidence, "vulnerability_scan")

        if vuln_scan is None:
            return self.warn("Missing vulnerability scan results")

        evidence_refs = [vuln_scan.hash or vuln_scan.evidence_id]
        scan_data = vuln_scan.data

        scan_date = scan_data.get("scan_date")
        critical_count = scan_data.get("critical_count", 0)
        high_count = scan_data.get("high_count", 0)
        medium_count = scan_data.get("medium_count", 0)

        # Check scan recency
        if scan_date:
            try:
                scan_datetime = datetime.fromisoformat(scan_date)
                days_since = (datetime.now(timezone.utc) - scan_datetime).days
                if days_since > self.parameters["max_days_since_scan"]:
                    return self.fail(
                        f"Last vulnerability scan was {days_since} days ago "
                        f"(max: {self.parameters['max_days_since_scan']})",
                        measurements={"days_since_scan": days_since},
                        evidence_refs=evidence_refs,
                    )
            except (ValueError, TypeError):
                return self.warn("Invalid scan date format")
        else:
            return self.fail(
                "No vulnerability scan date found",
                measurements={},
                evidence_refs=evidence_refs,
            )

        # Check critical vulnerabilities
        if critical_count > self.parameters["max_critical_unpatched"]:
            return self.fail(
                f"{critical_count} critical vulnerabilities unpatched "
                f"(max: {self.parameters['max_critical_unpatched']})",
                measurements={
                    "critical_count": critical_count,
                    "high_count": high_count,
                    "medium_count": medium_count,
                },
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "scan_date": scan_date,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
            },
            evidence_refs=evidence_refs,
        )


class SOC2CC72AnomalyDetectionPCU(BasePCU):
    """PCU-SOC2-CC7.2 — Anomaly Detection

    Predicate P-SOC2-CC7.2:
      The entity monitors system components and detects anomalies
      that could indicate security events.
    """

    pcu_id = "PCU-SOC2-CC7-2"
    version = "1.0.0"
    evaluates = ["P-SOC2-CC7.2"]
    framework = "soc2"
    description = "Validates anomaly detection and SIEM monitoring"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="siem_config",
            source="siem_platform",
            type="siem_configuration",
            required=True,
        ),
        EvidenceSpec(
            name="alert_metrics",
            source="siem_platform",
            type="alert_statistics",
            required=False,
        ),
    ]

    parameters = {
        "require_siem": True,
        "require_24x7_monitoring": True,
        "max_alert_ack_hours": 4,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        siem_config = self.get_evidence(evidence, "siem_configuration")

        if siem_config is None:
            return self.warn("Missing SIEM configuration evidence")

        evidence_refs = [siem_config.hash or siem_config.evidence_id]
        siem_data = siem_config.data

        siem_enabled = siem_data.get("siem_enabled", False)
        monitoring_24x7 = siem_data.get("monitoring_24x7", False)
        log_sources_count = siem_data.get("log_sources_count", 0)

        if self.parameters["require_siem"] and not siem_enabled:
            return self.fail(
                "SIEM not enabled",
                measurements={"siem_enabled": False},
                evidence_refs=evidence_refs,
            )

        if self.parameters["require_24x7_monitoring"] and not monitoring_24x7:
            return self.fail(
                "24x7 monitoring not enabled",
                measurements={"monitoring_24x7": False},
                evidence_refs=evidence_refs,
            )

        if log_sources_count == 0:
            return self.fail(
                "No log sources configured in SIEM",
                measurements={"log_sources_count": 0},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "siem_enabled": siem_enabled,
                "monitoring_24x7": monitoring_24x7,
                "log_sources_count": log_sources_count,
            },
            evidence_refs=evidence_refs,
        )


class SOC2CC73IncidentEvaluationPCU(BasePCU):
    """PCU-SOC2-CC7.3 — Incident Evaluation

    Predicate P-SOC2-CC7.3:
      The entity evaluates security events to determine whether
      they could or have resulted in a failure of the entity to
      meet its objectives (security incidents).
    """

    pcu_id = "PCU-SOC2-CC7-3"
    version = "1.0.0"
    evaluates = ["P-SOC2-CC7.3"]
    framework = "soc2"
    description = "Validates security incident evaluation process"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="incident_records",
            source="incident_management",
            type="security_incidents",
            required=True,
        ),
    ]

    parameters = {
        "require_severity_classification": True,
        "max_hours_to_evaluate": 24,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        incidents = self.get_evidence(evidence, "security_incidents")

        if incidents is None:
            return self.warn("Missing incident records")

        evidence_refs = [incidents.hash or incidents.evidence_id]
        incident_data = incidents.data

        total_incidents = incident_data.get("total_incidents", 0)
        evaluated_incidents = incident_data.get("evaluated_count", 0)
        classified_incidents = incident_data.get("classified_count", 0)
        avg_evaluation_hours = incident_data.get("avg_evaluation_hours", 0)

        if total_incidents == 0:
            return self.pass_result(
                measurements={"total_incidents": 0, "note": "No incidents in period"},
                evidence_refs=evidence_refs,
            )

        # Check evaluation completeness
        if evaluated_incidents < total_incidents:
            unevaluated = total_incidents - evaluated_incidents
            return self.fail(
                f"{unevaluated} incidents not evaluated",
                measurements={
                    "total_incidents": total_incidents,
                    "evaluated_incidents": evaluated_incidents,
                },
                evidence_refs=evidence_refs,
            )

        # Check classification
        if self.parameters["require_severity_classification"]:
            if classified_incidents < total_incidents:
                unclassified = total_incidents - classified_incidents
                return self.fail(
                    f"{unclassified} incidents not severity-classified",
                    measurements={
                        "total_incidents": total_incidents,
                        "classified_incidents": classified_incidents,
                    },
                    evidence_refs=evidence_refs,
                )

        # Check evaluation timeliness
        if avg_evaluation_hours > self.parameters["max_hours_to_evaluate"]:
            return self.fail(
                f"Average incident evaluation time {avg_evaluation_hours:.1f}h "
                f"exceeds threshold {self.parameters['max_hours_to_evaluate']}h",
                measurements={"avg_evaluation_hours": avg_evaluation_hours},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "total_incidents": total_incidents,
                "evaluated_incidents": evaluated_incidents,
                "avg_evaluation_hours": avg_evaluation_hours,
            },
            evidence_refs=evidence_refs,
        )


class SOC2CC74IncidentResponsePCU(BasePCU):
    """PCU-SOC2-CC7.4 — Incident Response

    Predicate P-SOC2-CC7.4:
      The entity responds to identified security incidents by executing
      a defined incident response program.
    """

    pcu_id = "PCU-SOC2-CC7-4"
    version = "1.0.0"
    evaluates = ["P-SOC2-CC7.4"]
    framework = "soc2"
    description = "Validates incident response program execution"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="ir_policy",
            source="policy_repo",
            type="incident_response_policy",
            required=True,
        ),
        EvidenceSpec(
            name="ir_metrics",
            source="incident_management",
            type="incident_response_metrics",
            required=True,
        ),
    ]

    parameters = {
        "require_ir_plan": True,
        "max_hours_to_contain_critical": 4,
        "max_hours_to_contain_high": 24,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        ir_policy = self.get_evidence(evidence, "incident_response_policy")
        ir_metrics = self.get_evidence(evidence, "incident_response_metrics")

        if ir_policy is None:
            return self.warn("Missing incident response policy")

        if ir_metrics is None:
            return self.warn("Missing incident response metrics")

        evidence_refs = [
            ir_policy.hash or ir_policy.evidence_id,
            ir_metrics.hash or ir_metrics.evidence_id,
        ]

        policy_data = ir_policy.data
        metrics_data = ir_metrics.data

        # Check IR plan exists
        if self.parameters["require_ir_plan"]:
            if not policy_data.get("ir_plan_exists", False):
                return self.fail(
                    "Incident response plan not documented",
                    measurements={"ir_plan_exists": False},
                    evidence_refs=evidence_refs,
                )

        # Check containment times
        avg_contain_critical = metrics_data.get("avg_containment_hours_critical", 0)
        avg_contain_high = metrics_data.get("avg_containment_hours_high", 0)

        if avg_contain_critical > self.parameters["max_hours_to_contain_critical"]:
            return self.fail(
                f"Critical incident containment time {avg_contain_critical:.1f}h "
                f"exceeds threshold {self.parameters['max_hours_to_contain_critical']}h",
                measurements={"avg_containment_hours_critical": avg_contain_critical},
                evidence_refs=evidence_refs,
            )

        if avg_contain_high > self.parameters["max_hours_to_contain_high"]:
            return self.fail(
                f"High severity incident containment time {avg_contain_high:.1f}h "
                f"exceeds threshold {self.parameters['max_hours_to_contain_high']}h",
                measurements={"avg_containment_hours_high": avg_contain_high},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "ir_plan_exists": True,
                "avg_containment_hours_critical": avg_contain_critical,
                "avg_containment_hours_high": avg_contain_high,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# CC8 — CHANGE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════


class SOC2CC81ChangeAuthorizationPCU(BasePCU):
    """PCU-SOC2-CC8.1 — Change Authorization

    Predicate P-SOC2-CC8.1:
      The entity authorizes, designs, develops or acquires, configures,
      documents, tests, approves, and implements changes to infrastructure,
      data, software, and procedures.
    """

    pcu_id = "PCU-SOC2-CC8-1"
    version = "1.0.0"
    evaluates = ["P-SOC2-CC8.1"]
    framework = "soc2"
    description = "Validates change management authorization process"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="change_records",
            source="change_management",
            type="change_tickets",
            required=True,
        ),
    ]

    parameters = {
        "require_approval": True,
        "require_testing": True,
        "max_unauthorized_changes_pct": 0.0,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        changes = self.get_evidence(evidence, "change_tickets")

        if changes is None:
            return self.warn("Missing change management records")

        evidence_refs = [changes.hash or changes.evidence_id]
        change_data = changes.data

        total_changes = change_data.get("total_changes", 0)
        approved_changes = change_data.get("approved_changes", 0)
        tested_changes = change_data.get("tested_changes", 0)
        emergency_changes = change_data.get("emergency_changes", 0)

        if total_changes == 0:
            return self.pass_result(
                measurements={"total_changes": 0, "note": "No changes in period"},
                evidence_refs=evidence_refs,
            )

        # Check approval rate
        unapproved = total_changes - approved_changes
        unapproved_pct = (unapproved / total_changes) * 100 if total_changes > 0 else 0

        if unapproved_pct > self.parameters["max_unauthorized_changes_pct"]:
            return self.fail(
                f"{unapproved} changes without approval ({unapproved_pct:.1f}%)",
                measurements={
                    "total_changes": total_changes,
                    "approved_changes": approved_changes,
                    "unapproved_pct": unapproved_pct,
                },
                evidence_refs=evidence_refs,
            )

        # Check testing
        if self.parameters["require_testing"]:
            untested = total_changes - tested_changes
            if untested > emergency_changes:  # Emergency changes may bypass testing
                return self.fail(
                    f"{untested - emergency_changes} non-emergency changes without testing",
                    measurements={
                        "total_changes": total_changes,
                        "tested_changes": tested_changes,
                        "emergency_changes": emergency_changes,
                    },
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "total_changes": total_changes,
                "approved_changes": approved_changes,
                "tested_changes": tested_changes,
                "emergency_changes": emergency_changes,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# CC4 — MONITORING ACTIVITIES
# ═══════════════════════════════════════════════════════════════════════════════


class SOC2CC41OngoingMonitoringPCU(BasePCU):
    """PCU-SOC2-CC4.1 — Ongoing Monitoring

    Predicate P-SOC2-CC4.1:
      The entity selects, develops, and performs ongoing and/or separate
      evaluations to ascertain whether the components of internal control
      are present and functioning.
    """

    pcu_id = "PCU-SOC2-CC4-1"
    version = "1.0.0"
    evaluates = ["P-SOC2-CC4.1"]
    framework = "soc2"
    description = "Validates ongoing monitoring activities"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="monitoring_config",
            source="monitoring_system",
            type="monitoring_configuration",
            required=True,
        ),
        EvidenceSpec(
            name="dashboard_metrics",
            source="monitoring_system",
            type="monitoring_metrics",
            required=False,
        ),
    ]

    parameters = {
        "require_automated_monitoring": True,
        "min_monitoring_coverage_pct": 90.0,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        monitoring = self.get_evidence(evidence, "monitoring_configuration")

        if monitoring is None:
            return self.warn("Missing monitoring configuration")

        evidence_refs = [monitoring.hash or monitoring.evidence_id]
        mon_data = monitoring.data

        automated_monitoring = mon_data.get("automated_monitoring_enabled", False)
        systems_monitored = mon_data.get("systems_monitored", 0)
        total_systems = mon_data.get("total_systems", 0)

        if self.parameters["require_automated_monitoring"] and not automated_monitoring:
            return self.fail(
                "Automated monitoring not enabled",
                measurements={"automated_monitoring_enabled": False},
                evidence_refs=evidence_refs,
            )

        if total_systems > 0:
            coverage_pct = (systems_monitored / total_systems) * 100
            if coverage_pct < self.parameters["min_monitoring_coverage_pct"]:
                return self.fail(
                    f"Monitoring coverage {coverage_pct:.1f}% below threshold "
                    f"{self.parameters['min_monitoring_coverage_pct']}%",
                    measurements={
                        "systems_monitored": systems_monitored,
                        "total_systems": total_systems,
                        "coverage_pct": coverage_pct,
                    },
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "automated_monitoring_enabled": automated_monitoring,
                "systems_monitored": systems_monitored,
                "total_systems": total_systems,
            },
            evidence_refs=evidence_refs,
        )


class SOC2CC42DeficiencyEvaluationPCU(BasePCU):
    """PCU-SOC2-CC4.2 — Deficiency Evaluation

    Predicate P-SOC2-CC4.2:
      The entity evaluates and communicates internal control deficiencies
      in a timely manner to those parties responsible for taking corrective
      action, including senior management and the board of directors.
    """

    pcu_id = "PCU-SOC2-CC4-2"
    version = "1.0.0"
    evaluates = ["P-SOC2-CC4.2"]
    framework = "soc2"
    description = "Validates control deficiency evaluation and remediation"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="audit_findings",
            source="audit_management",
            type="audit_findings",
            required=True,
        ),
        EvidenceSpec(
            name="remediation_tracking",
            source="audit_management",
            type="remediation_records",
            required=True,
        ),
    ]

    parameters = {
        "max_days_to_remediate_critical": 30,
        "max_days_to_remediate_high": 90,
        "max_overdue_findings_pct": 10.0,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        findings = self.get_evidence(evidence, "audit_findings")
        remediation = self.get_evidence(evidence, "remediation_records")

        if findings is None:
            return self.warn("Missing audit findings")

        if remediation is None:
            return self.warn("Missing remediation tracking records")

        evidence_refs = [
            findings.hash or findings.evidence_id,
            remediation.hash or remediation.evidence_id,
        ]

        findings_data = findings.data
        remediation_data = remediation.data

        total_findings = findings_data.get("total_findings", 0)
        critical_findings = findings_data.get("critical_findings", 0)
        overdue_remediations = remediation_data.get("overdue_count", 0)

        if total_findings == 0:
            return self.pass_result(
                measurements={"total_findings": 0, "note": "No findings in period"},
                evidence_refs=evidence_refs,
            )

        overdue_pct = (overdue_remediations / total_findings) * 100

        if overdue_pct > self.parameters["max_overdue_findings_pct"]:
            return self.fail(
                f"{overdue_remediations} overdue remediations ({overdue_pct:.1f}%) "
                f"exceeds threshold {self.parameters['max_overdue_findings_pct']}%",
                measurements={
                    "total_findings": total_findings,
                    "overdue_remediations": overdue_remediations,
                    "overdue_pct": overdue_pct,
                },
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "total_findings": total_findings,
                "critical_findings": critical_findings,
                "overdue_remediations": overdue_remediations,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# REGISTRATION
# ═══════════════════════════════════════════════════════════════════════════════


def register_soc2_pcus(registry: "PCURegistry") -> None:
    """Register all SOC 2 PCUs with the given registry."""
    pcus = [
        # CC6 - Access Controls
        SOC2CC61LogicalAccessPCU(),
        SOC2CC62CredentialManagementPCU(),
        SOC2CC63AccessRemovalPCU(),
        SOC2CC64AccessReviewPCU(),
        SOC2CC65PhysicalAccessPCU(),
        SOC2CC66ExternalThreatsPCU(),
        SOC2CC67TransmissionProtectionPCU(),
        SOC2CC68MalwareProtectionPCU(),
        # CC7 - System Operations
        SOC2CC71VulnerabilityDetectionPCU(),
        SOC2CC72AnomalyDetectionPCU(),
        SOC2CC73IncidentEvaluationPCU(),
        SOC2CC74IncidentResponsePCU(),
        # CC8 - Change Management
        SOC2CC81ChangeAuthorizationPCU(),
        # CC4 - Monitoring
        SOC2CC41OngoingMonitoringPCU(),
        SOC2CC42DeficiencyEvaluationPCU(),
    ]

    for pcu in pcus:
        registry.register(pcu)

    # Register predicate→gate mappings
    gate_mappings = {
        # CC6 - Security (G2)
        "P-SOC2-CC6.1": "G2",
        "P-SOC2-CC6.2": "G2",
        "P-SOC2-CC6.3": "G2",
        "P-SOC2-CC6.4": "G2",
        "P-SOC2-CC6.5": "G2",
        "P-SOC2-CC6.6": "G2",
        "P-SOC2-CC6.7": "G2",
        "P-SOC2-CC6.8": "G2",
        # CC7 - System Operations (G2)
        "P-SOC2-CC7.1": "G2",
        "P-SOC2-CC7.2": "G2",
        "P-SOC2-CC7.3": "G2",
        "P-SOC2-CC7.4": "G2",
        # CC8 - Change Management (G2)
        "P-SOC2-CC8.1": "G2",
        # CC4 - Monitoring (G8)
        "P-SOC2-CC4.1": "G8",
        "P-SOC2-CC4.2": "G8",
    }

    for pred_id, gate_id in gate_mappings.items():
        registry.register_predicate_gate_mapping(pred_id, gate_id)
        gate = registry.get_gate(gate_id)
        if gate and pred_id not in gate.predicate_ids:
            gate.predicate_ids.append(pred_id)

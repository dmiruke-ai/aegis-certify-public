"""
AEGIS Certify — PCI-DSS v4.0 PCU Implementations

Implements PCUs for PCI-DSS (Payment Card Industry Data Security Standard v4.0)
following the canonical 7-step pipeline:
  1. Fix the predicate (no drift)
  2. Identify observable variables
  3. Define evidence interfaces
  4. Define thresholds explicitly
  5. Implement deterministic logic
  6. Emit structured result
  7. Bind to predicate(s)

Reference: PCI DSS v4.0 (March 2022)
"""

from __future__ import annotations

from datetime import datetime, timezone
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
# REQUIREMENT 1 — BUILD AND MAINTAIN A SECURE NETWORK
# ═══════════════════════════════════════════════════════════════════════════════


class PCIDSSFirewallConfigPCU(BasePCU):
    """PCU-PCIDSS-1.1 — Firewall Configuration

    Predicate P-PCIDSS-1.1:
      Network security controls are installed, configured, and maintained to
      protect cardholder data environment (CDE) from unauthorized network traffic.

    Observable Variables:
      - firewall_deployed: bool
      - default_deny_policy: bool
      - rule_review_current: bool
      - cde_zones_defined: bool
    """

    pcu_id = "PCU-PCIDSS-1-1"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-1.1"]
    framework = "pci_dss"
    description = "Validates firewall configuration for CDE protection"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="firewall_config",
            source="network_security",
            type="firewall_configuration",
            required=True,
        ),
        EvidenceSpec(
            name="firewall_rules",
            source="network_security",
            type="firewall_rules",
            required=True,
        ),
    ]

    parameters = {
        "require_default_deny": True,
        "max_days_since_rule_review": 180,
        "require_cde_segmentation": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        fw_config = self.get_evidence(evidence, "firewall_configuration")
        fw_rules = self.get_evidence(evidence, "firewall_rules")

        if fw_config is None:
            return self.warn("Missing firewall configuration evidence")

        if fw_rules is None:
            return self.warn("Missing firewall rules evidence")

        evidence_refs = [
            fw_config.hash or fw_config.evidence_id,
            fw_rules.hash or fw_rules.evidence_id,
        ]

        config_data = fw_config.data
        rules_data = fw_rules.data

        # Check firewall deployment
        if not config_data.get("firewall_deployed", False):
            return self.fail(
                "Firewall not deployed for CDE protection",
                measurements={"firewall_deployed": False},
                evidence_refs=evidence_refs,
            )

        # Check default deny policy
        if self.parameters["require_default_deny"]:
            if not config_data.get("default_deny_inbound", False):
                return self.fail(
                    "Default-deny inbound policy not configured",
                    measurements={"default_deny_inbound": False},
                    evidence_refs=evidence_refs,
                )
            if not config_data.get("default_deny_outbound", False):
                return self.fail(
                    "Default-deny outbound policy not configured",
                    measurements={"default_deny_outbound": False},
                    evidence_refs=evidence_refs,
                )

        # Check CDE segmentation
        if self.parameters["require_cde_segmentation"]:
            if not config_data.get("cde_segmented", False):
                return self.fail(
                    "CDE not properly segmented from other networks",
                    measurements={"cde_segmented": False},
                    evidence_refs=evidence_refs,
                )

        # Check rule review date
        last_review = rules_data.get("last_rule_review_date")
        if last_review:
            try:
                review_date = datetime.fromisoformat(last_review)
                days_since = (datetime.now(timezone.utc) - review_date).days
                if days_since > self.parameters["max_days_since_rule_review"]:
                    return self.fail(
                        f"Firewall rules not reviewed in {days_since} days "
                        f"(max: {self.parameters['max_days_since_rule_review']})",
                        measurements={"days_since_rule_review": days_since},
                        evidence_refs=evidence_refs,
                    )
            except (ValueError, TypeError):
                return self.warn("Invalid rule review date format")
        else:
            return self.fail(
                "No firewall rule review date documented",
                measurements={},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "firewall_deployed": True,
                "default_deny_inbound": True,
                "default_deny_outbound": True,
                "cde_segmented": True,
                "days_since_rule_review": days_since,
            },
            evidence_refs=evidence_refs,
        )


class PCIDSSNetworkSegmentationPCU(BasePCU):
    """PCU-PCIDSS-1.4 — Network Segmentation

    Predicate P-PCIDSS-1.4:
      Network connections between trusted and untrusted networks are controlled
      and CDE is properly segmented.
    """

    pcu_id = "PCU-PCIDSS-1-4"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-1.4"]
    framework = "pci_dss"
    description = "Validates network segmentation controls"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="network_diagram",
            source="network_documentation",
            type="network_topology",
            required=True,
        ),
        EvidenceSpec(
            name="segmentation_test",
            source="security_testing",
            type="segmentation_validation",
            required=True,
        ),
    ]

    parameters = {
        "max_days_since_segmentation_test": 180,
        "require_documented_topology": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        network = self.get_evidence(evidence, "network_topology")
        seg_test = self.get_evidence(evidence, "segmentation_validation")

        if network is None:
            return self.warn("Missing network topology documentation")

        if seg_test is None:
            return self.warn("Missing segmentation validation test results")

        evidence_refs = [
            network.hash or network.evidence_id,
            seg_test.hash or seg_test.evidence_id,
        ]

        network_data = network.data
        test_data = seg_test.data

        # Check topology documentation
        if self.parameters["require_documented_topology"]:
            if not network_data.get("cde_boundary_documented", False):
                return self.fail(
                    "CDE boundary not documented in network diagram",
                    measurements={"cde_boundary_documented": False},
                    evidence_refs=evidence_refs,
                )

        # Check segmentation test
        test_date = test_data.get("test_date")
        test_passed = test_data.get("segmentation_effective", False)

        if not test_passed:
            return self.fail(
                "Segmentation test failed - CDE not properly isolated",
                measurements={"segmentation_effective": False},
                evidence_refs=evidence_refs,
            )

        if test_date:
            try:
                tested = datetime.fromisoformat(test_date)
                days_since = (datetime.now(timezone.utc) - tested).days
                if days_since > self.parameters["max_days_since_segmentation_test"]:
                    return self.fail(
                        f"Segmentation test performed {days_since} days ago "
                        f"(max: {self.parameters['max_days_since_segmentation_test']})",
                        measurements={"days_since_segmentation_test": days_since},
                        evidence_refs=evidence_refs,
                    )
            except (ValueError, TypeError):
                return self.warn("Invalid segmentation test date format")

        return self.pass_result(
            measurements={
                "cde_boundary_documented": True,
                "segmentation_effective": True,
                "days_since_segmentation_test": days_since if test_date else None,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# REQUIREMENT 2 — DEFAULT SECURITY CONFIGURATIONS
# ═══════════════════════════════════════════════════════════════════════════════


class PCIDSSDefaultConfigPCU(BasePCU):
    """PCU-PCIDSS-2.1 — Default Configuration Removal

    Predicate P-PCIDSS-2.1:
      Vendor-supplied defaults for system passwords and other security
      parameters are changed.
    """

    pcu_id = "PCU-PCIDSS-2-1"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-2.1"]
    framework = "pci_dss"
    description = "Validates removal of vendor-supplied defaults"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="config_audit",
            source="configuration_management",
            type="default_config_scan",
            required=True,
        ),
    ]

    parameters = {
        "max_default_credentials_found": 0,
        "max_default_services_enabled": 0,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        config_audit = self.get_evidence(evidence, "default_config_scan")

        if config_audit is None:
            return self.warn("Missing default configuration scan results")

        evidence_refs = [config_audit.hash or config_audit.evidence_id]
        audit_data = config_audit.data

        default_creds = audit_data.get("default_credentials_found", 0)
        default_services = audit_data.get("default_services_enabled", 0)
        unnecessary_services = audit_data.get("unnecessary_services_running", 0)

        if default_creds > self.parameters["max_default_credentials_found"]:
            return self.fail(
                f"{default_creds} systems with default credentials found",
                measurements={"default_credentials_found": default_creds},
                evidence_refs=evidence_refs,
            )

        if default_services > self.parameters["max_default_services_enabled"]:
            return self.fail(
                f"{default_services} systems with default services enabled",
                measurements={"default_services_enabled": default_services},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "default_credentials_found": default_creds,
                "default_services_enabled": default_services,
                "unnecessary_services_running": unnecessary_services,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# REQUIREMENT 3 — PROTECT STORED ACCOUNT DATA
# ═══════════════════════════════════════════════════════════════════════════════


class PCIDSSDataRetentionPCU(BasePCU):
    """PCU-PCIDSS-3.1 — Data Retention Policy

    Predicate P-PCIDSS-3.1:
      Account data storage is kept to a minimum through retention and
      disposal policies.
    """

    pcu_id = "PCU-PCIDSS-3-1"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-3.1"]
    framework = "pci_dss"
    description = "Validates data retention and disposal policies"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="retention_policy",
            source="policy_repo",
            type="data_retention_policy",
            required=True,
        ),
        EvidenceSpec(
            name="data_inventory",
            source="data_management",
            type="cardholder_data_inventory",
            required=True,
        ),
    ]

    parameters = {
        "max_retention_days": 365,
        "require_secure_deletion": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        policy = self.get_evidence(evidence, "data_retention_policy")
        inventory = self.get_evidence(evidence, "cardholder_data_inventory")

        if policy is None:
            return self.warn("Missing data retention policy")

        if inventory is None:
            return self.warn("Missing cardholder data inventory")

        evidence_refs = [
            policy.hash or policy.evidence_id,
            inventory.hash or inventory.evidence_id,
        ]

        policy_data = policy.data
        inv_data = inventory.data

        # Check policy exists
        if not policy_data.get("policy_defined", False):
            return self.fail(
                "Data retention policy not defined",
                measurements={"policy_defined": False},
                evidence_refs=evidence_refs,
            )

        # Check retention period
        retention_days = policy_data.get("retention_period_days", 999)
        if retention_days > self.parameters["max_retention_days"]:
            return self.fail(
                f"Retention period {retention_days} days exceeds maximum "
                f"{self.parameters['max_retention_days']} days",
                measurements={"retention_period_days": retention_days},
                evidence_refs=evidence_refs,
            )

        # Check for data exceeding retention
        data_beyond_retention = inv_data.get("records_beyond_retention", 0)
        if data_beyond_retention > 0:
            return self.fail(
                f"{data_beyond_retention} records exceed retention period",
                measurements={"records_beyond_retention": data_beyond_retention},
                evidence_refs=evidence_refs,
            )

        # Check secure deletion
        if self.parameters["require_secure_deletion"]:
            if not policy_data.get("secure_deletion_method", False):
                return self.fail(
                    "Secure deletion method not specified",
                    measurements={"secure_deletion_method": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "policy_defined": True,
                "retention_period_days": retention_days,
                "records_beyond_retention": 0,
                "secure_deletion_method": True,
            },
            evidence_refs=evidence_refs,
        )


class PCIDSSDataEncryptionPCU(BasePCU):
    """PCU-PCIDSS-3.5 — Stored Data Encryption

    Predicate P-PCIDSS-3.5:
      Primary Account Numbers (PAN) are rendered unreadable anywhere it is
      stored using strong cryptography.
    """

    pcu_id = "PCU-PCIDSS-3-5"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-3.5"]
    framework = "pci_dss"
    description = "Validates PAN encryption at rest"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="encryption_config",
            source="security_infrastructure",
            type="encryption_at_rest",
            required=True,
        ),
        EvidenceSpec(
            name="pan_scan",
            source="data_discovery",
            type="pan_discovery_scan",
            required=True,
        ),
    ]

    parameters = {
        "min_key_length_bits": 256,
        "approved_algorithms": ["AES-256", "AES-256-GCM", "RSA-4096"],
        "max_unencrypted_pan_locations": 0,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        encryption = self.get_evidence(evidence, "encryption_at_rest")
        pan_scan = self.get_evidence(evidence, "pan_discovery_scan")

        if encryption is None:
            return self.warn("Missing encryption configuration evidence")

        if pan_scan is None:
            return self.warn("Missing PAN discovery scan results")

        evidence_refs = [
            encryption.hash or encryption.evidence_id,
            pan_scan.hash or pan_scan.evidence_id,
        ]

        enc_data = encryption.data
        scan_data = pan_scan.data

        # Check encryption enabled
        if not enc_data.get("encryption_enabled", False):
            return self.fail(
                "Encryption at rest not enabled for PAN storage",
                measurements={"encryption_enabled": False},
                evidence_refs=evidence_refs,
            )

        # Check algorithm strength
        algorithm = enc_data.get("encryption_algorithm", "")
        if algorithm not in self.parameters["approved_algorithms"]:
            return self.fail(
                f"Encryption algorithm '{algorithm}' not in approved list",
                measurements={"encryption_algorithm": algorithm},
                evidence_refs=evidence_refs,
            )

        # Check key length
        key_length = enc_data.get("key_length_bits", 0)
        if key_length < self.parameters["min_key_length_bits"]:
            return self.fail(
                f"Key length {key_length} bits below minimum "
                f"{self.parameters['min_key_length_bits']} bits",
                measurements={"key_length_bits": key_length},
                evidence_refs=evidence_refs,
            )

        # Check for unencrypted PAN
        unencrypted_locations = scan_data.get("unencrypted_pan_locations", 0)
        if unencrypted_locations > self.parameters["max_unencrypted_pan_locations"]:
            return self.fail(
                f"{unencrypted_locations} locations with unencrypted PAN found",
                measurements={"unencrypted_pan_locations": unencrypted_locations},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "encryption_enabled": True,
                "encryption_algorithm": algorithm,
                "key_length_bits": key_length,
                "unencrypted_pan_locations": 0,
            },
            evidence_refs=evidence_refs,
        )


class PCIDSSKeyManagementPCU(BasePCU):
    """PCU-PCIDSS-3.6 — Cryptographic Key Management

    Predicate P-PCIDSS-3.6:
      Cryptographic keys used to protect stored account data are protected.
    """

    pcu_id = "PCU-PCIDSS-3-6"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-3.6"]
    framework = "pci_dss"
    description = "Validates cryptographic key management"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="key_management",
            source="security_infrastructure",
            type="key_management_config",
            required=True,
        ),
    ]

    parameters = {
        "require_hsm": True,
        "max_key_age_days": 365,
        "require_key_rotation_policy": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        kms_config = self.get_evidence(evidence, "key_management_config")

        if kms_config is None:
            return self.warn("Missing key management configuration")

        evidence_refs = [kms_config.hash or kms_config.evidence_id]
        kms_data = kms_config.data

        # Check KMS deployed
        if not kms_data.get("kms_deployed", False):
            return self.fail(
                "Key management system not deployed",
                measurements={"kms_deployed": False},
                evidence_refs=evidence_refs,
            )

        # Check HSM requirement
        if self.parameters["require_hsm"]:
            if not kms_data.get("hsm_enabled", False):
                return self.fail(
                    "HSM not used for key protection",
                    measurements={"hsm_enabled": False},
                    evidence_refs=evidence_refs,
                )

        # Check key rotation
        if self.parameters["require_key_rotation_policy"]:
            if not kms_data.get("rotation_policy_defined", False):
                return self.fail(
                    "Key rotation policy not defined",
                    measurements={"rotation_policy_defined": False},
                    evidence_refs=evidence_refs,
                )

        # Check oldest key age
        oldest_key_age = kms_data.get("oldest_key_age_days", 0)
        if oldest_key_age > self.parameters["max_key_age_days"]:
            return self.fail(
                f"Keys not rotated in {oldest_key_age} days "
                f"(max: {self.parameters['max_key_age_days']})",
                measurements={"oldest_key_age_days": oldest_key_age},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "kms_deployed": True,
                "hsm_enabled": kms_data.get("hsm_enabled", False),
                "rotation_policy_defined": True,
                "oldest_key_age_days": oldest_key_age,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# REQUIREMENT 4 — PROTECT DATA DURING TRANSMISSION
# ═══════════════════════════════════════════════════════════════════════════════


class PCIDSSTransmissionEncryptionPCU(BasePCU):
    """PCU-PCIDSS-4.1 — Transmission Encryption

    Predicate P-PCIDSS-4.1:
      Strong cryptography is used during transmission of cardholder data
      over open, public networks.
    """

    pcu_id = "PCU-PCIDSS-4-1"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-4.1"]
    framework = "pci_dss"
    description = "Validates encryption during data transmission"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="tls_config",
            source="network_security",
            type="tls_configuration",
            required=True,
        ),
        EvidenceSpec(
            name="certificate_scan",
            source="security_testing",
            type="ssl_scan_results",
            required=False,
        ),
    ]

    parameters = {
        "min_tls_version": "1.2",
        "prohibited_ciphers": ["RC4", "DES", "3DES", "MD5"],
        "require_pfs": True,  # Perfect Forward Secrecy
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

        # Check TLS enabled
        if not tls_data.get("tls_enabled", False):
            return self.fail(
                "TLS not enabled for transmission",
                measurements={"tls_enabled": False},
                evidence_refs=evidence_refs,
            )

        # Check TLS version
        min_version = tls_data.get("min_tls_version", "")
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

        # Check prohibited ciphers
        enabled_ciphers = tls_data.get("enabled_ciphers", [])
        for cipher in enabled_ciphers:
            for prohibited in self.parameters["prohibited_ciphers"]:
                if prohibited.lower() in cipher.lower():
                    return self.fail(
                        f"Prohibited cipher '{cipher}' enabled",
                        measurements={"prohibited_cipher": cipher},
                        evidence_refs=evidence_refs,
                    )

        # Check PFS
        if self.parameters["require_pfs"]:
            if not tls_data.get("pfs_enabled", False):
                return self.fail(
                    "Perfect Forward Secrecy not enabled",
                    measurements={"pfs_enabled": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "tls_enabled": True,
                "min_tls_version": min_version,
                "pfs_enabled": tls_data.get("pfs_enabled", False),
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# REQUIREMENT 5 — MALWARE PROTECTION
# ═══════════════════════════════════════════════════════════════════════════════


class PCIDSSMalwareProtectionPCU(BasePCU):
    """PCU-PCIDSS-5.2 — Anti-Malware Mechanisms

    Predicate P-PCIDSS-5.2:
      Anti-malware mechanisms are deployed on all systems commonly affected
      by malicious software.
    """

    pcu_id = "PCU-PCIDSS-5-2"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-5.2"]
    framework = "pci_dss"
    description = "Validates anti-malware deployment and updates"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="antimalware_status",
            source="endpoint_security",
            type="antimalware_deployment",
            required=True,
        ),
    ]

    parameters = {
        "min_coverage_pct": 100.0,  # All applicable systems
        "max_hours_since_update": 24,
        "require_real_time_protection": True,
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
            return self.warn("Missing anti-malware deployment status")

        evidence_refs = [av_status.hash or av_status.evidence_id]
        av_data = av_status.data

        # Check coverage
        total_systems = av_data.get("total_applicable_systems", 0)
        protected_systems = av_data.get("protected_systems", 0)

        if total_systems == 0:
            return self.warn("No applicable systems reported")

        coverage_pct = (protected_systems / total_systems) * 100
        if coverage_pct < self.parameters["min_coverage_pct"]:
            return self.fail(
                f"Anti-malware coverage {coverage_pct:.1f}% below required "
                f"{self.parameters['min_coverage_pct']}%",
                measurements={
                    "protected_systems": protected_systems,
                    "total_systems": total_systems,
                    "coverage_pct": coverage_pct,
                },
                evidence_refs=evidence_refs,
            )

        # Check definition updates
        hours_since_update = av_data.get("hours_since_definition_update", 999)
        if hours_since_update > self.parameters["max_hours_since_update"]:
            return self.fail(
                f"Malware definitions {hours_since_update} hours old "
                f"(max: {self.parameters['max_hours_since_update']})",
                measurements={"hours_since_definition_update": hours_since_update},
                evidence_refs=evidence_refs,
            )

        # Check real-time protection
        if self.parameters["require_real_time_protection"]:
            if not av_data.get("real_time_protection_enabled", False):
                return self.fail(
                    "Real-time malware protection not enabled",
                    measurements={"real_time_protection_enabled": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "coverage_pct": coverage_pct,
                "hours_since_definition_update": hours_since_update,
                "real_time_protection_enabled": True,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# REQUIREMENT 6 — SECURE DEVELOPMENT
# ═══════════════════════════════════════════════════════════════════════════════


class PCIDSSSecureDevelopmentPCU(BasePCU):
    """PCU-PCIDSS-6.2 — Secure Development Practices

    Predicate P-PCIDSS-6.2:
      Software is developed securely and custom code is reviewed prior to
      release to production.
    """

    pcu_id = "PCU-PCIDSS-6-2"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-6.2"]
    framework = "pci_dss"
    description = "Validates secure software development practices"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="sdlc_policy",
            source="development",
            type="secure_sdlc_policy",
            required=True,
        ),
        EvidenceSpec(
            name="code_review_records",
            source="development",
            type="code_review_metrics",
            required=True,
        ),
    ]

    parameters = {
        "require_secure_coding_training": True,
        "min_code_review_coverage_pct": 100.0,
        "require_sast": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        sdlc = self.get_evidence(evidence, "secure_sdlc_policy")
        reviews = self.get_evidence(evidence, "code_review_metrics")

        if sdlc is None:
            return self.warn("Missing secure SDLC policy")

        if reviews is None:
            return self.warn("Missing code review records")

        evidence_refs = [
            sdlc.hash or sdlc.evidence_id,
            reviews.hash or reviews.evidence_id,
        ]

        sdlc_data = sdlc.data
        review_data = reviews.data

        # Check SDLC policy
        if not sdlc_data.get("secure_sdlc_defined", False):
            return self.fail(
                "Secure SDLC policy not defined",
                measurements={"secure_sdlc_defined": False},
                evidence_refs=evidence_refs,
            )

        # Check secure coding training
        if self.parameters["require_secure_coding_training"]:
            if not sdlc_data.get("secure_coding_training_required", False):
                return self.fail(
                    "Secure coding training not required",
                    measurements={"secure_coding_training_required": False},
                    evidence_refs=evidence_refs,
                )

        # Check code review coverage
        total_changes = review_data.get("total_code_changes", 0)
        reviewed_changes = review_data.get("reviewed_changes", 0)

        if total_changes > 0:
            review_coverage = (reviewed_changes / total_changes) * 100
            if review_coverage < self.parameters["min_code_review_coverage_pct"]:
                return self.fail(
                    f"Code review coverage {review_coverage:.1f}% below required "
                    f"{self.parameters['min_code_review_coverage_pct']}%",
                    measurements={
                        "total_code_changes": total_changes,
                        "reviewed_changes": reviewed_changes,
                        "review_coverage_pct": review_coverage,
                    },
                    evidence_refs=evidence_refs,
                )

        # Check SAST requirement
        if self.parameters["require_sast"]:
            if not sdlc_data.get("sast_enabled", False):
                return self.fail(
                    "Static Application Security Testing (SAST) not enabled",
                    measurements={"sast_enabled": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "secure_sdlc_defined": True,
                "secure_coding_training_required": True,
                "review_coverage_pct": 100.0 if total_changes == 0 else review_coverage,
                "sast_enabled": True,
            },
            evidence_refs=evidence_refs,
        )


class PCIDSSChangeControlPCU(BasePCU):
    """PCU-PCIDSS-6.5 — Change Control Procedures

    Predicate P-PCIDSS-6.5:
      Changes to system components are managed and tracked through a
      formal change control process.
    """

    pcu_id = "PCU-PCIDSS-6-5"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-6.5"]
    framework = "pci_dss"
    description = "Validates change control procedures"
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
        "require_change_approval": True,
        "require_rollback_plan": True,
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
            return self.warn("Missing change control records")

        evidence_refs = [changes.hash or changes.evidence_id]
        change_data = changes.data

        total_changes = change_data.get("total_changes", 0)
        approved_changes = change_data.get("approved_changes", 0)
        changes_with_rollback = change_data.get("changes_with_rollback_plan", 0)

        if total_changes == 0:
            return self.pass_result(
                measurements={"total_changes": 0, "note": "No changes in period"},
                evidence_refs=evidence_refs,
            )

        # Check approval rate
        unapproved_pct = ((total_changes - approved_changes) / total_changes) * 100
        if unapproved_pct > self.parameters["max_unauthorized_changes_pct"]:
            return self.fail(
                f"{total_changes - approved_changes} changes without approval "
                f"({unapproved_pct:.1f}%)",
                measurements={
                    "total_changes": total_changes,
                    "approved_changes": approved_changes,
                    "unapproved_pct": unapproved_pct,
                },
                evidence_refs=evidence_refs,
            )

        # Check rollback plans
        if self.parameters["require_rollback_plan"]:
            rollback_pct = (changes_with_rollback / total_changes) * 100
            if rollback_pct < 100.0:
                return self.fail(
                    f"Only {rollback_pct:.1f}% of changes have rollback plans",
                    measurements={
                        "changes_with_rollback_plan": changes_with_rollback,
                        "total_changes": total_changes,
                    },
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "total_changes": total_changes,
                "approved_changes": approved_changes,
                "changes_with_rollback_plan": changes_with_rollback,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# REQUIREMENT 7 — ACCESS CONTROL
# ═══════════════════════════════════════════════════════════════════════════════


class PCIDSSAccessRestrictionPCU(BasePCU):
    """PCU-PCIDSS-7.1 — Access Restriction by Business Need

    Predicate P-PCIDSS-7.1:
      Access to cardholder data is restricted to personnel with a legitimate
      business need.
    """

    pcu_id = "PCU-PCIDSS-7-1"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-7.1"]
    framework = "pci_dss"
    description = "Validates access restriction to cardholder data"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="access_control_policy",
            source="policy_repo",
            type="access_control_policy",
            required=True,
        ),
        EvidenceSpec(
            name="access_review",
            source="iam_system",
            type="cde_access_review",
            required=True,
        ),
    ]

    parameters = {
        "require_need_to_know": True,
        "require_least_privilege": True,
        "max_days_since_access_review": 90,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        policy = self.get_evidence(evidence, "access_control_policy")
        review = self.get_evidence(evidence, "cde_access_review")

        if policy is None:
            return self.warn("Missing access control policy")

        if review is None:
            return self.warn("Missing CDE access review records")

        evidence_refs = [
            policy.hash or policy.evidence_id,
            review.hash or review.evidence_id,
        ]

        policy_data = policy.data
        review_data = review.data

        # Check need-to-know policy
        if self.parameters["require_need_to_know"]:
            if not policy_data.get("need_to_know_enforced", False):
                return self.fail(
                    "Need-to-know access not enforced",
                    measurements={"need_to_know_enforced": False},
                    evidence_refs=evidence_refs,
                )

        # Check least privilege
        if self.parameters["require_least_privilege"]:
            if not policy_data.get("least_privilege_enforced", False):
                return self.fail(
                    "Least privilege principle not enforced",
                    measurements={"least_privilege_enforced": False},
                    evidence_refs=evidence_refs,
                )

        # Check access review recency
        last_review = review_data.get("last_review_date")
        if last_review:
            try:
                review_date = datetime.fromisoformat(last_review)
                days_since = (datetime.now(timezone.utc) - review_date).days
                if days_since > self.parameters["max_days_since_access_review"]:
                    return self.fail(
                        f"CDE access not reviewed in {days_since} days "
                        f"(max: {self.parameters['max_days_since_access_review']})",
                        measurements={"days_since_access_review": days_since},
                        evidence_refs=evidence_refs,
                    )
            except (ValueError, TypeError):
                return self.warn("Invalid access review date format")
        else:
            return self.fail(
                "No CDE access review date documented",
                measurements={},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "need_to_know_enforced": True,
                "least_privilege_enforced": True,
                "days_since_access_review": days_since,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# REQUIREMENT 8 — AUTHENTICATION
# ═══════════════════════════════════════════════════════════════════════════════


class PCIDSSAuthenticationPCU(BasePCU):
    """PCU-PCIDSS-8.3 — Strong Authentication

    Predicate P-PCIDSS-8.3:
      Strong authentication mechanisms are used for user authentication.
    """

    pcu_id = "PCU-PCIDSS-8-3"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-8.3"]
    framework = "pci_dss"
    description = "Validates strong authentication requirements"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="auth_config",
            source="iam_system",
            type="authentication_configuration",
            required=True,
        ),
        EvidenceSpec(
            name="password_policy",
            source="iam_system",
            type="password_policy",
            required=True,
        ),
    ]

    parameters = {
        "min_password_length": 12,
        "require_complexity": True,
        "max_password_age_days": 90,
        "lockout_threshold": 6,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        auth = self.get_evidence(evidence, "authentication_configuration")
        pw_policy = self.get_evidence(evidence, "password_policy")

        if auth is None:
            return self.warn("Missing authentication configuration")

        if pw_policy is None:
            return self.warn("Missing password policy")

        evidence_refs = [
            auth.hash or auth.evidence_id,
            pw_policy.hash or pw_policy.evidence_id,
        ]

        auth_data = auth.data
        pw_data = pw_policy.data

        # Check unique IDs
        if not auth_data.get("unique_user_ids", False):
            return self.fail(
                "Unique user IDs not enforced",
                measurements={"unique_user_ids": False},
                evidence_refs=evidence_refs,
            )

        # Check password length
        min_length = pw_data.get("min_password_length", 0)
        if min_length < self.parameters["min_password_length"]:
            return self.fail(
                f"Minimum password length {min_length} below required "
                f"{self.parameters['min_password_length']}",
                measurements={"min_password_length": min_length},
                evidence_refs=evidence_refs,
            )

        # Check complexity
        if self.parameters["require_complexity"]:
            if not pw_data.get("complexity_required", False):
                return self.fail(
                    "Password complexity not required",
                    measurements={"complexity_required": False},
                    evidence_refs=evidence_refs,
                )

        # Check lockout
        lockout = pw_data.get("lockout_threshold", 999)
        if lockout > self.parameters["lockout_threshold"]:
            return self.fail(
                f"Account lockout threshold {lockout} exceeds maximum "
                f"{self.parameters['lockout_threshold']}",
                measurements={"lockout_threshold": lockout},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "unique_user_ids": True,
                "min_password_length": min_length,
                "complexity_required": True,
                "lockout_threshold": lockout,
            },
            evidence_refs=evidence_refs,
        )


class PCIDSSMFAPCu(BasePCU):
    """PCU-PCIDSS-8.4 — Multi-Factor Authentication

    Predicate P-PCIDSS-8.4:
      Multi-factor authentication is implemented for access to the CDE.
    """

    pcu_id = "PCU-PCIDSS-8-4"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-8.4"]
    framework = "pci_dss"
    description = "Validates MFA implementation for CDE access"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="mfa_config",
            source="iam_system",
            type="mfa_configuration",
            required=True,
        ),
    ]

    parameters = {
        "require_mfa_for_cde": True,
        "require_mfa_for_admin": True,
        "require_mfa_for_remote": True,
        "min_mfa_coverage_pct": 100.0,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        mfa = self.get_evidence(evidence, "mfa_configuration")

        if mfa is None:
            return self.warn("Missing MFA configuration")

        evidence_refs = [mfa.hash or mfa.evidence_id]
        mfa_data = mfa.data

        # Check MFA for CDE access
        if self.parameters["require_mfa_for_cde"]:
            if not mfa_data.get("mfa_cde_access", False):
                return self.fail(
                    "MFA not required for CDE access",
                    measurements={"mfa_cde_access": False},
                    evidence_refs=evidence_refs,
                )

        # Check MFA for admin access
        if self.parameters["require_mfa_for_admin"]:
            if not mfa_data.get("mfa_admin_access", False):
                return self.fail(
                    "MFA not required for administrative access",
                    measurements={"mfa_admin_access": False},
                    evidence_refs=evidence_refs,
                )

        # Check MFA for remote access
        if self.parameters["require_mfa_for_remote"]:
            if not mfa_data.get("mfa_remote_access", False):
                return self.fail(
                    "MFA not required for remote access",
                    measurements={"mfa_remote_access": False},
                    evidence_refs=evidence_refs,
                )

        # Check MFA coverage
        total_users = mfa_data.get("total_cde_users", 0)
        mfa_enabled_users = mfa_data.get("mfa_enabled_users", 0)

        if total_users > 0:
            coverage_pct = (mfa_enabled_users / total_users) * 100
            if coverage_pct < self.parameters["min_mfa_coverage_pct"]:
                return self.fail(
                    f"MFA coverage {coverage_pct:.1f}% below required "
                    f"{self.parameters['min_mfa_coverage_pct']}%",
                    measurements={
                        "total_cde_users": total_users,
                        "mfa_enabled_users": mfa_enabled_users,
                        "mfa_coverage_pct": coverage_pct,
                    },
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "mfa_cde_access": True,
                "mfa_admin_access": True,
                "mfa_remote_access": True,
                "mfa_coverage_pct": 100.0,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# REQUIREMENT 9 — PHYSICAL SECURITY
# ═══════════════════════════════════════════════════════════════════════════════


class PCIDSSPhysicalAccessPCU(BasePCU):
    """PCU-PCIDSS-9.1 — Physical Access Control

    Predicate P-PCIDSS-9.1:
      Physical access to cardholder data environments is appropriately
      restricted and monitored.
    """

    pcu_id = "PCU-PCIDSS-9-1"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-9.1"]
    framework = "pci_dss"
    description = "Validates physical access controls"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="physical_access_logs",
            source="physical_security",
            type="badge_access_logs",
            required=True,
        ),
        EvidenceSpec(
            name="visitor_logs",
            source="physical_security",
            type="visitor_records",
            required=True,
        ),
    ]

    parameters = {
        "require_badge_access": True,
        "require_visitor_escort": True,
        "max_unauthorized_access_events": 0,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        badge_logs = self.get_evidence(evidence, "badge_access_logs")
        visitor_logs = self.get_evidence(evidence, "visitor_records")

        if badge_logs is None:
            return self.warn("Missing badge access logs")

        if visitor_logs is None:
            return self.warn("Missing visitor records")

        evidence_refs = [
            badge_logs.hash or badge_logs.evidence_id,
            visitor_logs.hash or visitor_logs.evidence_id,
        ]

        badge_data = badge_logs.data
        visitor_data = visitor_logs.data

        # Check badge system
        if self.parameters["require_badge_access"]:
            if not badge_data.get("badge_system_active", False):
                return self.fail(
                    "Badge access system not active",
                    measurements={"badge_system_active": False},
                    evidence_refs=evidence_refs,
                )

        # Check unauthorized access
        unauthorized = badge_data.get("unauthorized_access_events", 0)
        if unauthorized > self.parameters["max_unauthorized_access_events"]:
            return self.fail(
                f"{unauthorized} unauthorized physical access events detected",
                measurements={"unauthorized_access_events": unauthorized},
                evidence_refs=evidence_refs,
            )

        # Check visitor escort
        if self.parameters["require_visitor_escort"]:
            unescorted_visitors = visitor_data.get("unescorted_visitors", 0)
            if unescorted_visitors > 0:
                return self.fail(
                    f"{unescorted_visitors} visitors without escort",
                    measurements={"unescorted_visitors": unescorted_visitors},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "badge_system_active": True,
                "unauthorized_access_events": unauthorized,
                "unescorted_visitors": 0,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# REQUIREMENT 10 — LOGGING AND MONITORING
# ═══════════════════════════════════════════════════════════════════════════════


class PCIDSSAuditLoggingPCU(BasePCU):
    """PCU-PCIDSS-10.2 — Audit Logging

    Predicate P-PCIDSS-10.2:
      Audit logs record all user access to cardholder data and all actions
      by individuals with administrative access.
    """

    pcu_id = "PCU-PCIDSS-10-2"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-10.2"]
    framework = "pci_dss"
    description = "Validates audit logging requirements"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="logging_config",
            source="logging_system",
            type="audit_log_configuration",
            required=True,
        ),
    ]

    parameters = {
        "require_user_access_logging": True,
        "require_admin_action_logging": True,
        "require_security_event_logging": True,
        "min_log_retention_days": 365,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        logging = self.get_evidence(evidence, "audit_log_configuration")

        if logging is None:
            return self.warn("Missing audit logging configuration")

        evidence_refs = [logging.hash or logging.evidence_id]
        log_data = logging.data

        # Check user access logging
        if self.parameters["require_user_access_logging"]:
            if not log_data.get("user_access_logging", False):
                return self.fail(
                    "User access to cardholder data not logged",
                    measurements={"user_access_logging": False},
                    evidence_refs=evidence_refs,
                )

        # Check admin action logging
        if self.parameters["require_admin_action_logging"]:
            if not log_data.get("admin_action_logging", False):
                return self.fail(
                    "Administrative actions not logged",
                    measurements={"admin_action_logging": False},
                    evidence_refs=evidence_refs,
                )

        # Check security event logging
        if self.parameters["require_security_event_logging"]:
            if not log_data.get("security_event_logging", False):
                return self.fail(
                    "Security events not logged",
                    measurements={"security_event_logging": False},
                    evidence_refs=evidence_refs,
                )

        # Check retention
        retention_days = log_data.get("log_retention_days", 0)
        if retention_days < self.parameters["min_log_retention_days"]:
            return self.fail(
                f"Log retention {retention_days} days below minimum "
                f"{self.parameters['min_log_retention_days']} days",
                measurements={"log_retention_days": retention_days},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "user_access_logging": True,
                "admin_action_logging": True,
                "security_event_logging": True,
                "log_retention_days": retention_days,
            },
            evidence_refs=evidence_refs,
        )


class PCIDSSLogReviewPCU(BasePCU):
    """PCU-PCIDSS-10.6 — Log Review

    Predicate P-PCIDSS-10.6:
      Audit logs are reviewed at least daily to identify anomalies or
      suspicious activity.
    """

    pcu_id = "PCU-PCIDSS-10-6"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-10.6"]
    framework = "pci_dss"
    description = "Validates log review procedures"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="log_review_records",
            source="security_operations",
            type="log_review_records",
            required=True,
        ),
    ]

    parameters = {
        "max_hours_between_reviews": 24,
        "require_automated_alerting": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        reviews = self.get_evidence(evidence, "log_review_records")

        if reviews is None:
            return self.warn("Missing log review records")

        evidence_refs = [reviews.hash or reviews.evidence_id]
        review_data = reviews.data

        # Check review frequency
        hours_since_last_review = review_data.get("hours_since_last_review", 999)
        if hours_since_last_review > self.parameters["max_hours_between_reviews"]:
            return self.fail(
                f"Logs not reviewed in {hours_since_last_review} hours "
                f"(max: {self.parameters['max_hours_between_reviews']})",
                measurements={"hours_since_last_review": hours_since_last_review},
                evidence_refs=evidence_refs,
            )

        # Check automated alerting
        if self.parameters["require_automated_alerting"]:
            if not review_data.get("automated_alerting_enabled", False):
                return self.fail(
                    "Automated log alerting not enabled",
                    measurements={"automated_alerting_enabled": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "hours_since_last_review": hours_since_last_review,
                "automated_alerting_enabled": True,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# REQUIREMENT 11 — SECURITY TESTING
# ═══════════════════════════════════════════════════════════════════════════════


class PCIDSSVulnerabilityScanPCU(BasePCU):
    """PCU-PCIDSS-11.3 — Vulnerability Scanning

    Predicate P-PCIDSS-11.3:
      Internal and external vulnerability scans are performed regularly.
    """

    pcu_id = "PCU-PCIDSS-11-3"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-11.3"]
    framework = "pci_dss"
    description = "Validates vulnerability scanning requirements"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="internal_scan",
            source="vulnerability_scanner",
            type="internal_vulnerability_scan",
            required=True,
        ),
        EvidenceSpec(
            name="external_scan",
            source="asv_provider",
            type="external_vulnerability_scan",
            required=True,
        ),
    ]

    parameters = {
        "max_days_since_internal_scan": 90,
        "max_days_since_external_scan": 90,
        "max_high_severity_vulns": 0,
        "require_asv_passing": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        internal = self.get_evidence(evidence, "internal_vulnerability_scan")
        external = self.get_evidence(evidence, "external_vulnerability_scan")

        if internal is None:
            return self.warn("Missing internal vulnerability scan")

        if external is None:
            return self.warn("Missing external vulnerability scan (ASV)")

        evidence_refs = [
            internal.hash or internal.evidence_id,
            external.hash or external.evidence_id,
        ]

        internal_data = internal.data
        external_data = external.data

        # Check internal scan date
        internal_date = internal_data.get("scan_date")
        if internal_date:
            try:
                scan_date = datetime.fromisoformat(internal_date)
                days_since = (datetime.now(timezone.utc) - scan_date).days
                if days_since > self.parameters["max_days_since_internal_scan"]:
                    return self.fail(
                        f"Internal scan performed {days_since} days ago "
                        f"(max: {self.parameters['max_days_since_internal_scan']})",
                        measurements={"days_since_internal_scan": days_since},
                        evidence_refs=evidence_refs,
                    )
            except (ValueError, TypeError):
                return self.warn("Invalid internal scan date format")

        # Check external scan date
        external_date = external_data.get("scan_date")
        if external_date:
            try:
                scan_date = datetime.fromisoformat(external_date)
                days_since = (datetime.now(timezone.utc) - scan_date).days
                if days_since > self.parameters["max_days_since_external_scan"]:
                    return self.fail(
                        f"External scan performed {days_since} days ago "
                        f"(max: {self.parameters['max_days_since_external_scan']})",
                        measurements={"days_since_external_scan": days_since},
                        evidence_refs=evidence_refs,
                    )
            except (ValueError, TypeError):
                return self.warn("Invalid external scan date format")

        # Check ASV passing status
        if self.parameters["require_asv_passing"]:
            if not external_data.get("asv_passing", False):
                return self.fail(
                    "ASV scan not passing",
                    measurements={"asv_passing": False},
                    evidence_refs=evidence_refs,
                )

        # Check high severity vulnerabilities
        high_vulns = internal_data.get("high_severity_count", 0) + external_data.get(
            "high_severity_count", 0
        )
        if high_vulns > self.parameters["max_high_severity_vulns"]:
            return self.fail(
                f"{high_vulns} high severity vulnerabilities found",
                measurements={"high_severity_count": high_vulns},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "internal_scan_date": internal_date,
                "external_scan_date": external_date,
                "asv_passing": True,
                "high_severity_count": high_vulns,
            },
            evidence_refs=evidence_refs,
        )


class PCIDSSPenetrationTestPCU(BasePCU):
    """PCU-PCIDSS-11.4 — Penetration Testing

    Predicate P-PCIDSS-11.4:
      Penetration testing is performed at least annually and after
      significant changes.
    """

    pcu_id = "PCU-PCIDSS-11-4"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-11.4"]
    framework = "pci_dss"
    description = "Validates penetration testing requirements"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="pentest_report",
            source="security_testing",
            type="penetration_test_report",
            required=True,
        ),
    ]

    parameters = {
        "max_days_since_pentest": 365,
        "require_external_pentest": True,
        "require_internal_pentest": True,
        "max_critical_findings_unresolved": 0,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        pentest = self.get_evidence(evidence, "penetration_test_report")

        if pentest is None:
            return self.warn("Missing penetration test report")

        evidence_refs = [pentest.hash or pentest.evidence_id]
        pentest_data = pentest.data

        # Check pentest date
        test_date = pentest_data.get("test_date")
        if test_date:
            try:
                tested = datetime.fromisoformat(test_date)
                days_since = (datetime.now(timezone.utc) - tested).days
                if days_since > self.parameters["max_days_since_pentest"]:
                    return self.fail(
                        f"Penetration test performed {days_since} days ago "
                        f"(max: {self.parameters['max_days_since_pentest']})",
                        measurements={"days_since_pentest": days_since},
                        evidence_refs=evidence_refs,
                    )
            except (ValueError, TypeError):
                return self.warn("Invalid penetration test date format")
        else:
            return self.fail(
                "No penetration test date documented",
                measurements={},
                evidence_refs=evidence_refs,
            )

        # Check external pentest performed
        if self.parameters["require_external_pentest"]:
            if not pentest_data.get("external_pentest_performed", False):
                return self.fail(
                    "External penetration test not performed",
                    measurements={"external_pentest_performed": False},
                    evidence_refs=evidence_refs,
                )

        # Check internal pentest performed
        if self.parameters["require_internal_pentest"]:
            if not pentest_data.get("internal_pentest_performed", False):
                return self.fail(
                    "Internal penetration test not performed",
                    measurements={"internal_pentest_performed": False},
                    evidence_refs=evidence_refs,
                )

        # Check critical findings
        critical_unresolved = pentest_data.get("critical_findings_unresolved", 0)
        if critical_unresolved > self.parameters["max_critical_findings_unresolved"]:
            return self.fail(
                f"{critical_unresolved} critical pentest findings unresolved",
                measurements={"critical_findings_unresolved": critical_unresolved},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "test_date": test_date,
                "days_since_pentest": days_since,
                "external_pentest_performed": True,
                "internal_pentest_performed": True,
                "critical_findings_unresolved": critical_unresolved,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# REQUIREMENT 12 — SECURITY POLICY
# ═══════════════════════════════════════════════════════════════════════════════


class PCIDSSSecurityPolicyPCU(BasePCU):
    """PCU-PCIDSS-12.1 — Information Security Policy

    Predicate P-PCIDSS-12.1:
      An information security policy is established, published, maintained,
      and disseminated to all relevant personnel.
    """

    pcu_id = "PCU-PCIDSS-12-1"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-12.1"]
    framework = "pci_dss"
    description = "Validates information security policy requirements"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="security_policy",
            source="policy_repo",
            type="information_security_policy",
            required=True,
        ),
    ]

    parameters = {
        "max_days_since_review": 365,
        "require_annual_review": True,
        "require_acknowledgment": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        policy = self.get_evidence(evidence, "information_security_policy")

        if policy is None:
            return self.warn("Missing information security policy")

        evidence_refs = [policy.hash or policy.evidence_id]
        policy_data = policy.data

        # Check policy exists
        if not policy_data.get("policy_documented", False):
            return self.fail(
                "Information security policy not documented",
                measurements={"policy_documented": False},
                evidence_refs=evidence_refs,
            )

        # Check review date
        if self.parameters["require_annual_review"]:
            last_review = policy_data.get("last_review_date")
            if last_review:
                try:
                    review_date = datetime.fromisoformat(last_review)
                    days_since = (datetime.now(timezone.utc) - review_date).days
                    if days_since > self.parameters["max_days_since_review"]:
                        return self.fail(
                            f"Policy not reviewed in {days_since} days "
                            f"(max: {self.parameters['max_days_since_review']})",
                            measurements={"days_since_review": days_since},
                            evidence_refs=evidence_refs,
                        )
                except (ValueError, TypeError):
                    return self.warn("Invalid policy review date format")
            else:
                return self.fail(
                    "No policy review date documented",
                    measurements={},
                    evidence_refs=evidence_refs,
                )

        # Check acknowledgment
        if self.parameters["require_acknowledgment"]:
            if not policy_data.get("personnel_acknowledgment", False):
                return self.fail(
                    "Personnel policy acknowledgment not tracked",
                    measurements={"personnel_acknowledgment": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "policy_documented": True,
                "days_since_review": days_since if last_review else None,
                "personnel_acknowledgment": True,
            },
            evidence_refs=evidence_refs,
        )


class PCIDSSIncidentResponsePCU(BasePCU):
    """PCU-PCIDSS-12.10 — Incident Response Plan

    Predicate P-PCIDSS-12.10:
      An incident response plan is implemented and ready to be activated
      in the event of a suspected or confirmed security incident.
    """

    pcu_id = "PCU-PCIDSS-12-10"
    version = "1.0.0"
    evaluates = ["P-PCIDSS-12.10"]
    framework = "pci_dss"
    description = "Validates incident response plan"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="ir_plan",
            source="policy_repo",
            type="incident_response_plan",
            required=True,
        ),
        EvidenceSpec(
            name="ir_testing",
            source="security_operations",
            type="ir_test_records",
            required=True,
        ),
    ]

    parameters = {
        "require_ir_plan": True,
        "max_days_since_ir_test": 365,
        "require_24x7_coverage": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        ir_plan = self.get_evidence(evidence, "incident_response_plan")
        ir_testing = self.get_evidence(evidence, "ir_test_records")

        if ir_plan is None:
            return self.warn("Missing incident response plan")

        if ir_testing is None:
            return self.warn("Missing incident response test records")

        evidence_refs = [
            ir_plan.hash or ir_plan.evidence_id,
            ir_testing.hash or ir_testing.evidence_id,
        ]

        plan_data = ir_plan.data
        test_data = ir_testing.data

        # Check IR plan exists
        if self.parameters["require_ir_plan"]:
            if not plan_data.get("ir_plan_documented", False):
                return self.fail(
                    "Incident response plan not documented",
                    measurements={"ir_plan_documented": False},
                    evidence_refs=evidence_refs,
                )

        # Check 24x7 coverage
        if self.parameters["require_24x7_coverage"]:
            if not plan_data.get("24x7_coverage", False):
                return self.fail(
                    "24x7 incident response coverage not established",
                    measurements={"24x7_coverage": False},
                    evidence_refs=evidence_refs,
                )

        # Check IR testing
        last_test = test_data.get("last_test_date")
        if last_test:
            try:
                test_date = datetime.fromisoformat(last_test)
                days_since = (datetime.now(timezone.utc) - test_date).days
                if days_since > self.parameters["max_days_since_ir_test"]:
                    return self.fail(
                        f"Incident response plan not tested in {days_since} days "
                        f"(max: {self.parameters['max_days_since_ir_test']})",
                        measurements={"days_since_ir_test": days_since},
                        evidence_refs=evidence_refs,
                    )
            except (ValueError, TypeError):
                return self.warn("Invalid IR test date format")
        else:
            return self.fail(
                "No incident response test date documented",
                measurements={},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "ir_plan_documented": True,
                "24x7_coverage": True,
                "days_since_ir_test": days_since,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# REGISTRATION
# ═══════════════════════════════════════════════════════════════════════════════


def register_pci_dss_pcus(registry: "PCURegistry") -> None:
    """Register all PCI-DSS PCUs with the given registry."""
    pcus = [
        # Requirement 1 - Network Security
        PCIDSSFirewallConfigPCU(),
        PCIDSSNetworkSegmentationPCU(),
        # Requirement 2 - Default Configurations
        PCIDSSDefaultConfigPCU(),
        # Requirement 3 - Stored Data Protection
        PCIDSSDataRetentionPCU(),
        PCIDSSDataEncryptionPCU(),
        PCIDSSKeyManagementPCU(),
        # Requirement 4 - Transmission Security
        PCIDSSTransmissionEncryptionPCU(),
        # Requirement 5 - Malware Protection
        PCIDSSMalwareProtectionPCU(),
        # Requirement 6 - Secure Development
        PCIDSSSecureDevelopmentPCU(),
        PCIDSSChangeControlPCU(),
        # Requirement 7 - Access Control
        PCIDSSAccessRestrictionPCU(),
        # Requirement 8 - Authentication
        PCIDSSAuthenticationPCU(),
        PCIDSSMFAPCu(),
        # Requirement 9 - Physical Security
        PCIDSSPhysicalAccessPCU(),
        # Requirement 10 - Logging and Monitoring
        PCIDSSAuditLoggingPCU(),
        PCIDSSLogReviewPCU(),
        # Requirement 11 - Security Testing
        PCIDSSVulnerabilityScanPCU(),
        PCIDSSPenetrationTestPCU(),
        # Requirement 12 - Security Policy
        PCIDSSSecurityPolicyPCU(),
        PCIDSSIncidentResponsePCU(),
    ]

    for pcu in pcus:
        registry.register(pcu)

    # Register predicate→gate mappings
    gate_mappings = {
        # Requirement 1 - Network Security (G2 - Safety)
        "P-PCIDSS-1.1": "G2",
        "P-PCIDSS-1.4": "G2",
        # Requirement 2 - Default Configurations (G2)
        "P-PCIDSS-2.1": "G2",
        # Requirement 3 - Data Protection (G3 - Data Governance)
        "P-PCIDSS-3.1": "G3",
        "P-PCIDSS-3.5": "G3",
        "P-PCIDSS-3.6": "G3",
        # Requirement 4 - Transmission (G3)
        "P-PCIDSS-4.1": "G3",
        # Requirement 5 - Malware (G2)
        "P-PCIDSS-5.2": "G2",
        # Requirement 6 - Secure Development (G4 - Risk Management)
        "P-PCIDSS-6.2": "G4",
        "P-PCIDSS-6.5": "G4",
        # Requirement 7 - Access Control (G2)
        "P-PCIDSS-7.1": "G2",
        # Requirement 8 - Authentication (G2)
        "P-PCIDSS-8.3": "G2",
        "P-PCIDSS-8.4": "G2",
        # Requirement 9 - Physical Security (G2)
        "P-PCIDSS-9.1": "G2",
        # Requirement 10 - Logging (G6 - Audit Evidence)
        "P-PCIDSS-10.2": "G6",
        "P-PCIDSS-10.6": "G6",
        # Requirement 11 - Security Testing (G8 - Continuous Monitoring)
        "P-PCIDSS-11.3": "G8",
        "P-PCIDSS-11.4": "G8",
        # Requirement 12 - Security Policy (G1 - Legal Admissibility)
        "P-PCIDSS-12.1": "G1",
        "P-PCIDSS-12.10": "G1",
    }

    for pred_id, gate_id in gate_mappings.items():
        registry.register_predicate_gate_mapping(pred_id, gate_id)
        gate = registry.get_gate(gate_id)
        if gate and pred_id not in gate.predicate_ids:
            gate.predicate_ids.append(pred_id)

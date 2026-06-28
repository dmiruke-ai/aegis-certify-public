"""
AEGIS Certify — HIPAA Security Rule PCU Implementations

Implements PCUs for HIPAA Security Rule (45 CFR Part 164) following the
canonical 7-step pipeline.

Reference: HHS HIPAA Security Rule (45 CFR Part 164 Subpart C)
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
# 164.308 — ADMINISTRATIVE SAFEGUARDS
# ═══════════════════════════════════════════════════════════════════════════════


class HIPAARiskAnalysisPCU(BasePCU):
    """PCU-HIPAA-RISK-ANALYSIS — 164.308(a)(1)(ii)(A)

    Predicate P-HIPAA-308-A1-R:
      Conduct an accurate and thorough assessment of the potential risks
      and vulnerabilities to the confidentiality, integrity, and availability
      of electronic protected health information (ePHI).
    """

    pcu_id = "PCU-HIPAA-RISK-ANALYSIS"
    version = "1.0.0"
    evaluates = ["P-HIPAA-308-A1-R"]
    framework = "hipaa"
    description = "Validates HIPAA risk analysis requirement"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="risk_assessment",
            source="risk_management",
            type="hipaa_risk_assessment",
            required=True,
        ),
    ]

    parameters = {
        "max_days_since_assessment": 365,
        "require_ephi_inventory": True,
        "require_threat_identification": True,
        "require_vulnerability_assessment": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        risk_assessment = self.get_evidence(evidence, "hipaa_risk_assessment")

        if risk_assessment is None:
            return self.warn("Missing HIPAA risk assessment evidence")

        evidence_refs = [risk_assessment.hash or risk_assessment.evidence_id]
        ra_data = risk_assessment.data

        # Check assessment date
        assessment_date = ra_data.get("assessment_date")
        if assessment_date:
            try:
                assess_dt = datetime.fromisoformat(assessment_date)
                days_since = (datetime.now(timezone.utc) - assess_dt).days
                if days_since > self.parameters["max_days_since_assessment"]:
                    return self.fail(
                        f"Risk assessment {days_since} days old "
                        f"(max: {self.parameters['max_days_since_assessment']})",
                        measurements={"days_since_assessment": days_since},
                        evidence_refs=evidence_refs,
                    )
            except (ValueError, TypeError):
                return self.warn("Invalid assessment date format")
        else:
            return self.fail(
                "No risk assessment date found",
                measurements={},
                evidence_refs=evidence_refs,
            )

        # Check required components
        if self.parameters["require_ephi_inventory"]:
            if not ra_data.get("ephi_inventory_complete", False):
                return self.fail(
                    "ePHI inventory not complete in risk assessment",
                    measurements={"ephi_inventory_complete": False},
                    evidence_refs=evidence_refs,
                )

        if self.parameters["require_threat_identification"]:
            threats_identified = ra_data.get("threats_identified", 0)
            if threats_identified == 0:
                return self.fail(
                    "No threats identified in risk assessment",
                    measurements={"threats_identified": 0},
                    evidence_refs=evidence_refs,
                )

        if self.parameters["require_vulnerability_assessment"]:
            vulns_assessed = ra_data.get("vulnerabilities_assessed", 0)
            if vulns_assessed == 0:
                return self.fail(
                    "No vulnerabilities assessed",
                    measurements={"vulnerabilities_assessed": 0},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "assessment_date": assessment_date,
                "ephi_inventory_complete": ra_data.get("ephi_inventory_complete"),
                "threats_identified": ra_data.get("threats_identified"),
                "vulnerabilities_assessed": ra_data.get("vulnerabilities_assessed"),
            },
            evidence_refs=evidence_refs,
        )


class HIPAASanctionPolicyPCU(BasePCU):
    """PCU-HIPAA-SANCTIONS — 164.308(a)(1)(ii)(C)

    Predicate P-HIPAA-308-A1-S:
      Apply appropriate sanctions against workforce members who fail
      to comply with security policies and procedures.
    """

    pcu_id = "PCU-HIPAA-SANCTIONS"
    version = "1.0.0"
    evaluates = ["P-HIPAA-308-A1-S"]
    framework = "hipaa"
    description = "Validates sanction policy for security violations"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="sanction_policy",
            source="hr_policies",
            type="sanction_policy",
            required=True,
        ),
    ]

    parameters = {
        "require_documented_policy": True,
        "require_escalation_levels": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        sanction_policy = self.get_evidence(evidence, "sanction_policy")

        if sanction_policy is None:
            return self.warn("Missing sanction policy evidence")

        evidence_refs = [sanction_policy.hash or sanction_policy.evidence_id]
        policy_data = sanction_policy.data

        if self.parameters["require_documented_policy"]:
            if not policy_data.get("policy_documented", False):
                return self.fail(
                    "Sanction policy not documented",
                    measurements={"policy_documented": False},
                    evidence_refs=evidence_refs,
                )

        if self.parameters["require_escalation_levels"]:
            if not policy_data.get("escalation_levels_defined", False):
                return self.fail(
                    "Sanction escalation levels not defined",
                    measurements={"escalation_levels_defined": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "policy_documented": policy_data.get("policy_documented"),
                "escalation_levels_defined": policy_data.get("escalation_levels_defined"),
                "last_reviewed": policy_data.get("last_reviewed"),
            },
            evidence_refs=evidence_refs,
        )


class HIPAASecurityOfficerPCU(BasePCU):
    """PCU-HIPAA-SEC-OFFICER — 164.308(a)(2)

    Predicate P-HIPAA-308-A2:
      Identify the security official who is responsible for the development
      and implementation of the policies and procedures.
    """

    pcu_id = "PCU-HIPAA-SEC-OFFICER"
    version = "1.0.0"
    evaluates = ["P-HIPAA-308-A2"]
    framework = "hipaa"
    description = "Validates security officer designation"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="security_officer_doc",
            source="hr_records",
            type="security_officer_designation",
            required=True,
        ),
    ]

    parameters = {
        "require_named_individual": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        officer_doc = self.get_evidence(evidence, "security_officer_designation")

        if officer_doc is None:
            return self.warn("Missing security officer designation evidence")

        evidence_refs = [officer_doc.hash or officer_doc.evidence_id]
        officer_data = officer_doc.data

        if self.parameters["require_named_individual"]:
            officer_name = officer_data.get("officer_name")
            if not officer_name:
                return self.fail(
                    "Security officer not designated by name",
                    measurements={"officer_designated": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "officer_name": officer_data.get("officer_name"),
                "designation_date": officer_data.get("designation_date"),
                "contact_info": officer_data.get("contact_info") is not None,
            },
            evidence_refs=evidence_refs,
        )


class HIPAAWorkforceSecurityPCU(BasePCU):
    """PCU-HIPAA-WORKFORCE — 164.308(a)(3)

    Predicate P-HIPAA-308-A3:
      Implement policies and procedures to ensure that all members of its
      workforce have appropriate access to ePHI and to prevent unauthorized
      access by workforce members.
    """

    pcu_id = "PCU-HIPAA-WORKFORCE"
    version = "1.0.0"
    evaluates = ["P-HIPAA-308-A3"]
    framework = "hipaa"
    description = "Validates workforce security controls"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="authorization_records",
            source="iam_system",
            type="ephi_access_authorization",
            required=True,
        ),
        EvidenceSpec(
            name="termination_records",
            source="hr_system",
            type="termination_procedures",
            required=True,
        ),
    ]

    parameters = {
        "max_hours_to_terminate_access": 24,
        "require_background_checks": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        auth_records = self.get_evidence(evidence, "ephi_access_authorization")
        term_records = self.get_evidence(evidence, "termination_procedures")

        if auth_records is None:
            return self.warn("Missing ePHI access authorization records")

        if term_records is None:
            return self.warn("Missing termination procedure records")

        evidence_refs = [
            auth_records.hash or auth_records.evidence_id,
            term_records.hash or term_records.evidence_id,
        ]

        auth_data = auth_records.data
        term_data = term_records.data

        # Check authorization process
        if not auth_data.get("authorization_process_documented", False):
            return self.fail(
                "ePHI access authorization process not documented",
                measurements={"authorization_process_documented": False},
                evidence_refs=evidence_refs,
            )

        # Check termination timeliness
        avg_term_hours = term_data.get("avg_access_termination_hours", 0)
        if avg_term_hours > self.parameters["max_hours_to_terminate_access"]:
            return self.fail(
                f"Average access termination time {avg_term_hours}h exceeds "
                f"threshold {self.parameters['max_hours_to_terminate_access']}h",
                measurements={"avg_access_termination_hours": avg_term_hours},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "authorization_process_documented": True,
                "avg_access_termination_hours": avg_term_hours,
                "background_checks_performed": auth_data.get("background_checks_performed"),
            },
            evidence_refs=evidence_refs,
        )


class HIPAASecurityTrainingPCU(BasePCU):
    """PCU-HIPAA-TRAINING — 164.308(a)(5)

    Predicate P-HIPAA-308-A5:
      Implement a security awareness and training program for all members
      of its workforce (including management).
    """

    pcu_id = "PCU-HIPAA-TRAINING"
    version = "1.0.0"
    evaluates = ["P-HIPAA-308-A5"]
    framework = "hipaa"
    description = "Validates security awareness training program"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="training_records",
            source="lms",
            type="security_training_records",
            required=True,
        ),
    ]

    parameters = {
        "min_training_completion_pct": 95.0,
        "max_days_since_training": 365,
        "require_new_hire_training": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        training = self.get_evidence(evidence, "security_training_records")

        if training is None:
            return self.warn("Missing security training records")

        evidence_refs = [training.hash or training.evidence_id]
        training_data = training.data

        total_workforce = training_data.get("total_workforce", 0)
        trained_count = training_data.get("trained_count", 0)

        if total_workforce == 0:
            return self.warn("No workforce data available")

        completion_pct = (trained_count / total_workforce) * 100

        if completion_pct < self.parameters["min_training_completion_pct"]:
            return self.fail(
                f"Training completion {completion_pct:.1f}% below threshold "
                f"{self.parameters['min_training_completion_pct']}%",
                measurements={
                    "trained_count": trained_count,
                    "total_workforce": total_workforce,
                    "completion_pct": completion_pct,
                },
                evidence_refs=evidence_refs,
            )

        # Check new hire training
        if self.parameters["require_new_hire_training"]:
            new_hires_untrained = training_data.get("new_hires_untrained", 0)
            if new_hires_untrained > 0:
                return self.fail(
                    f"{new_hires_untrained} new hires without security training",
                    measurements={"new_hires_untrained": new_hires_untrained},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "trained_count": trained_count,
                "total_workforce": total_workforce,
                "completion_pct": completion_pct,
                "training_topics": training_data.get("topics_covered", []),
            },
            evidence_refs=evidence_refs,
        )


class HIPAAIncidentProceduresPCU(BasePCU):
    """PCU-HIPAA-INCIDENT — 164.308(a)(6)

    Predicate P-HIPAA-308-A6:
      Implement policies and procedures to address security incidents.
    """

    pcu_id = "PCU-HIPAA-INCIDENT"
    version = "1.0.0"
    evaluates = ["P-HIPAA-308-A6"]
    framework = "hipaa"
    description = "Validates security incident procedures"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="incident_policy",
            source="policy_repo",
            type="incident_response_policy",
            required=True,
        ),
        EvidenceSpec(
            name="incident_log",
            source="incident_management",
            type="incident_log",
            required=False,
        ),
    ]

    parameters = {
        "require_documented_procedures": True,
        "require_breach_notification_process": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        incident_policy = self.get_evidence(evidence, "incident_response_policy")

        if incident_policy is None:
            return self.warn("Missing incident response policy")

        evidence_refs = [incident_policy.hash or incident_policy.evidence_id]
        policy_data = incident_policy.data

        if self.parameters["require_documented_procedures"]:
            if not policy_data.get("procedures_documented", False):
                return self.fail(
                    "Incident response procedures not documented",
                    measurements={"procedures_documented": False},
                    evidence_refs=evidence_refs,
                )

        if self.parameters["require_breach_notification_process"]:
            if not policy_data.get("breach_notification_process", False):
                return self.fail(
                    "Breach notification process not documented",
                    measurements={"breach_notification_process": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "procedures_documented": True,
                "breach_notification_process": True,
                "last_drill_date": policy_data.get("last_drill_date"),
            },
            evidence_refs=evidence_refs,
        )


class HIPAAContingencyPlanPCU(BasePCU):
    """PCU-HIPAA-CONTINGENCY — 164.308(a)(7)

    Predicate P-HIPAA-308-A7:
      Establish (and implement as needed) policies and procedures for
      responding to an emergency or other occurrence that damages systems
      containing ePHI.
    """

    pcu_id = "PCU-HIPAA-CONTINGENCY"
    version = "1.0.0"
    evaluates = ["P-HIPAA-308-A7"]
    framework = "hipaa"
    description = "Validates contingency plan requirements"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="contingency_plan",
            source="policy_repo",
            type="contingency_plan",
            required=True,
        ),
        EvidenceSpec(
            name="backup_records",
            source="backup_system",
            type="backup_verification",
            required=True,
        ),
    ]

    parameters = {
        "require_data_backup_plan": True,
        "require_disaster_recovery_plan": True,
        "require_emergency_mode_plan": True,
        "max_days_since_backup_test": 90,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        contingency = self.get_evidence(evidence, "contingency_plan")
        backups = self.get_evidence(evidence, "backup_verification")

        if contingency is None:
            return self.warn("Missing contingency plan")

        if backups is None:
            return self.warn("Missing backup verification records")

        evidence_refs = [
            contingency.hash or contingency.evidence_id,
            backups.hash or backups.evidence_id,
        ]

        plan_data = contingency.data
        backup_data = backups.data

        # Check required plans
        if self.parameters["require_data_backup_plan"]:
            if not plan_data.get("data_backup_plan", False):
                return self.fail(
                    "Data backup plan not documented",
                    measurements={"data_backup_plan": False},
                    evidence_refs=evidence_refs,
                )

        if self.parameters["require_disaster_recovery_plan"]:
            if not plan_data.get("disaster_recovery_plan", False):
                return self.fail(
                    "Disaster recovery plan not documented",
                    measurements={"disaster_recovery_plan": False},
                    evidence_refs=evidence_refs,
                )

        if self.parameters["require_emergency_mode_plan"]:
            if not plan_data.get("emergency_mode_plan", False):
                return self.fail(
                    "Emergency mode operation plan not documented",
                    measurements={"emergency_mode_plan": False},
                    evidence_refs=evidence_refs,
                )

        # Check backup testing
        last_test_date = backup_data.get("last_restore_test_date")
        if last_test_date:
            try:
                test_dt = datetime.fromisoformat(last_test_date)
                days_since = (datetime.now(timezone.utc) - test_dt).days
                if days_since > self.parameters["max_days_since_backup_test"]:
                    return self.fail(
                        f"Backup restore test {days_since} days old "
                        f"(max: {self.parameters['max_days_since_backup_test']})",
                        measurements={"days_since_backup_test": days_since},
                        evidence_refs=evidence_refs,
                    )
            except (ValueError, TypeError):
                pass

        return self.pass_result(
            measurements={
                "data_backup_plan": True,
                "disaster_recovery_plan": True,
                "emergency_mode_plan": True,
                "last_restore_test_date": last_test_date,
            },
            evidence_refs=evidence_refs,
        )


class HIPAAEvaluationPCU(BasePCU):
    """PCU-HIPAA-EVALUATION — 164.308(a)(8)

    Predicate P-HIPAA-308-A8:
      Perform a periodic technical and nontechnical evaluation to
      establish the extent to which security policies and procedures
      meet the requirements.
    """

    pcu_id = "PCU-HIPAA-EVALUATION"
    version = "1.0.0"
    evaluates = ["P-HIPAA-308-A8"]
    framework = "hipaa"
    description = "Validates periodic security evaluation"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="evaluation_records",
            source="audit_management",
            type="hipaa_evaluation",
            required=True,
        ),
    ]

    parameters = {
        "max_days_since_evaluation": 365,
        "require_technical_evaluation": True,
        "require_nontechnical_evaluation": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        evaluation = self.get_evidence(evidence, "hipaa_evaluation")

        if evaluation is None:
            return self.warn("Missing HIPAA evaluation records")

        evidence_refs = [evaluation.hash or evaluation.evidence_id]
        eval_data = evaluation.data

        # Check evaluation date
        eval_date = eval_data.get("evaluation_date")
        if eval_date:
            try:
                eval_dt = datetime.fromisoformat(eval_date)
                days_since = (datetime.now(timezone.utc) - eval_dt).days
                if days_since > self.parameters["max_days_since_evaluation"]:
                    return self.fail(
                        f"Last HIPAA evaluation {days_since} days old "
                        f"(max: {self.parameters['max_days_since_evaluation']})",
                        measurements={"days_since_evaluation": days_since},
                        evidence_refs=evidence_refs,
                    )
            except (ValueError, TypeError):
                return self.warn("Invalid evaluation date format")
        else:
            return self.fail(
                "No HIPAA evaluation date found",
                measurements={},
                evidence_refs=evidence_refs,
            )

        # Check evaluation components
        if self.parameters["require_technical_evaluation"]:
            if not eval_data.get("technical_evaluation_complete", False):
                return self.fail(
                    "Technical evaluation not complete",
                    measurements={"technical_evaluation_complete": False},
                    evidence_refs=evidence_refs,
                )

        if self.parameters["require_nontechnical_evaluation"]:
            if not eval_data.get("nontechnical_evaluation_complete", False):
                return self.fail(
                    "Non-technical evaluation not complete",
                    measurements={"nontechnical_evaluation_complete": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "evaluation_date": eval_date,
                "technical_evaluation_complete": True,
                "nontechnical_evaluation_complete": True,
                "findings_count": eval_data.get("findings_count", 0),
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 164.310 — PHYSICAL SAFEGUARDS
# ═══════════════════════════════════════════════════════════════════════════════


class HIPAAFacilityAccessPCU(BasePCU):
    """PCU-HIPAA-FACILITY — 164.310(a)(1)

    Predicate P-HIPAA-310-A1:
      Implement policies and procedures to limit physical access to
      electronic information systems and the facility in which they
      are housed.
    """

    pcu_id = "PCU-HIPAA-FACILITY"
    version = "1.0.0"
    evaluates = ["P-HIPAA-310-A1"]
    framework = "hipaa"
    description = "Validates facility access controls"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="facility_access",
            source="physical_security",
            type="facility_access_controls",
            required=True,
        ),
    ]

    parameters = {
        "require_access_control_system": True,
        "require_visitor_procedures": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        facility = self.get_evidence(evidence, "facility_access_controls")

        if facility is None:
            return self.warn("Missing facility access control evidence")

        evidence_refs = [facility.hash or facility.evidence_id]
        facility_data = facility.data

        if self.parameters["require_access_control_system"]:
            if not facility_data.get("access_control_system_deployed", False):
                return self.fail(
                    "Physical access control system not deployed",
                    measurements={"access_control_system_deployed": False},
                    evidence_refs=evidence_refs,
                )

        if self.parameters["require_visitor_procedures"]:
            if not facility_data.get("visitor_procedures_documented", False):
                return self.fail(
                    "Visitor access procedures not documented",
                    measurements={"visitor_procedures_documented": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "access_control_system_deployed": True,
                "visitor_procedures_documented": True,
                "ephi_areas_secured": facility_data.get("ephi_areas_secured", False),
            },
            evidence_refs=evidence_refs,
        )


class HIPAAWorkstationSecurityPCU(BasePCU):
    """PCU-HIPAA-WORKSTATION — 164.310(b)(1) & 164.310(c)

    Predicate P-HIPAA-310-B1:
      Implement policies and procedures that specify the proper functions
      to be performed, the manner in which those functions are to be
      performed, and the physical attributes of the surroundings of a
      workstation or class of workstation that can access ePHI.
    """

    pcu_id = "PCU-HIPAA-WORKSTATION"
    version = "1.0.0"
    evaluates = ["P-HIPAA-310-B1"]
    framework = "hipaa"
    description = "Validates workstation use and security policies"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="workstation_policy",
            source="policy_repo",
            type="workstation_security_policy",
            required=True,
        ),
    ]

    parameters = {
        "require_workstation_policy": True,
        "require_physical_safeguards": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        policy = self.get_evidence(evidence, "workstation_security_policy")

        if policy is None:
            return self.warn("Missing workstation security policy")

        evidence_refs = [policy.hash or policy.evidence_id]
        policy_data = policy.data

        if self.parameters["require_workstation_policy"]:
            if not policy_data.get("policy_documented", False):
                return self.fail(
                    "Workstation security policy not documented",
                    measurements={"policy_documented": False},
                    evidence_refs=evidence_refs,
                )

        if self.parameters["require_physical_safeguards"]:
            if not policy_data.get("physical_safeguards_defined", False):
                return self.fail(
                    "Workstation physical safeguards not defined",
                    measurements={"physical_safeguards_defined": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "policy_documented": True,
                "physical_safeguards_defined": True,
                "screen_lock_required": policy_data.get("screen_lock_required", False),
            },
            evidence_refs=evidence_refs,
        )


class HIPAADeviceMediaControlsPCU(BasePCU):
    """PCU-HIPAA-DEVICE-MEDIA — 164.310(d)(1)

    Predicate P-HIPAA-310-D1:
      Implement policies and procedures that govern the receipt and
      removal of hardware and electronic media containing ePHI into
      and out of a facility, and the movement of these items within
      the facility.
    """

    pcu_id = "PCU-HIPAA-DEVICE-MEDIA"
    version = "1.0.0"
    evaluates = ["P-HIPAA-310-D1"]
    framework = "hipaa"
    description = "Validates device and media controls"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="media_policy",
            source="policy_repo",
            type="media_handling_policy",
            required=True,
        ),
        EvidenceSpec(
            name="disposal_records",
            source="asset_management",
            type="media_disposal_records",
            required=False,
        ),
    ]

    parameters = {
        "require_disposal_procedures": True,
        "require_reuse_procedures": True,
        "require_accountability": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        media_policy = self.get_evidence(evidence, "media_handling_policy")

        if media_policy is None:
            return self.warn("Missing media handling policy")

        evidence_refs = [media_policy.hash or media_policy.evidence_id]
        policy_data = media_policy.data

        if self.parameters["require_disposal_procedures"]:
            if not policy_data.get("disposal_procedures_documented", False):
                return self.fail(
                    "Media disposal procedures not documented",
                    measurements={"disposal_procedures_documented": False},
                    evidence_refs=evidence_refs,
                )

        if self.parameters["require_reuse_procedures"]:
            if not policy_data.get("reuse_procedures_documented", False):
                return self.fail(
                    "Media re-use/sanitization procedures not documented",
                    measurements={"reuse_procedures_documented": False},
                    evidence_refs=evidence_refs,
                )

        if self.parameters["require_accountability"]:
            if not policy_data.get("accountability_tracking", False):
                return self.fail(
                    "Media accountability/tracking not implemented",
                    measurements={"accountability_tracking": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "disposal_procedures_documented": True,
                "reuse_procedures_documented": True,
                "accountability_tracking": True,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 164.312 — TECHNICAL SAFEGUARDS
# ═══════════════════════════════════════════════════════════════════════════════


class HIPAAAccessControlPCU(BasePCU):
    """PCU-HIPAA-ACCESS-CTRL — 164.312(a)(1)

    Predicate P-HIPAA-312-A1:
      Implement technical policies and procedures for electronic
      information systems that maintain ePHI to allow access only
      to those persons or software programs that have been granted
      access rights.
    """

    pcu_id = "PCU-HIPAA-ACCESS-CTRL"
    version = "1.0.0"
    evaluates = ["P-HIPAA-312-A1"]
    framework = "hipaa"
    description = "Validates technical access control mechanisms"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="access_control_config",
            source="iam_system",
            type="access_control_configuration",
            required=True,
        ),
    ]

    parameters = {
        "require_unique_user_id": True,
        "require_emergency_access_procedure": True,
        "require_auto_logoff": True,
        "require_encryption": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        access_config = self.get_evidence(evidence, "access_control_configuration")

        if access_config is None:
            return self.warn("Missing access control configuration")

        evidence_refs = [access_config.hash or access_config.evidence_id]
        config_data = access_config.data

        if self.parameters["require_unique_user_id"]:
            if not config_data.get("unique_user_ids_enforced", False):
                return self.fail(
                    "Unique user identification not enforced",
                    measurements={"unique_user_ids_enforced": False},
                    evidence_refs=evidence_refs,
                )

        if self.parameters["require_emergency_access_procedure"]:
            if not config_data.get("emergency_access_procedure", False):
                return self.fail(
                    "Emergency access procedure not implemented",
                    measurements={"emergency_access_procedure": False},
                    evidence_refs=evidence_refs,
                )

        if self.parameters["require_auto_logoff"]:
            if not config_data.get("automatic_logoff_enabled", False):
                return self.fail(
                    "Automatic logoff not enabled",
                    measurements={"automatic_logoff_enabled": False},
                    evidence_refs=evidence_refs,
                )

        if self.parameters["require_encryption"]:
            if not config_data.get("encryption_enabled", False):
                return self.fail(
                    "Encryption not enabled for ePHI access",
                    measurements={"encryption_enabled": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "unique_user_ids_enforced": True,
                "emergency_access_procedure": True,
                "automatic_logoff_enabled": True,
                "encryption_enabled": True,
                "session_timeout_minutes": config_data.get("session_timeout_minutes"),
            },
            evidence_refs=evidence_refs,
        )


class HIPAAAuditControlsPCU(BasePCU):
    """PCU-HIPAA-AUDIT — 164.312(b)

    Predicate P-HIPAA-312-B:
      Implement hardware, software, and/or procedural mechanisms that
      record and examine activity in information systems that contain
      or use ePHI.
    """

    pcu_id = "PCU-HIPAA-AUDIT"
    version = "1.0.0"
    evaluates = ["P-HIPAA-312-B"]
    framework = "hipaa"
    description = "Validates audit control mechanisms"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="audit_config",
            source="logging_system",
            type="audit_configuration",
            required=True,
        ),
    ]

    parameters = {
        "require_access_logging": True,
        "require_log_review": True,
        "min_retention_days": 365,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        audit_config = self.get_evidence(evidence, "audit_configuration")

        if audit_config is None:
            return self.warn("Missing audit configuration evidence")

        evidence_refs = [audit_config.hash or audit_config.evidence_id]
        config_data = audit_config.data

        if self.parameters["require_access_logging"]:
            if not config_data.get("ephi_access_logging_enabled", False):
                return self.fail(
                    "ePHI access logging not enabled",
                    measurements={"ephi_access_logging_enabled": False},
                    evidence_refs=evidence_refs,
                )

        retention_days = config_data.get("log_retention_days", 0)
        if retention_days < self.parameters["min_retention_days"]:
            return self.fail(
                f"Log retention {retention_days} days below minimum "
                f"{self.parameters['min_retention_days']} days",
                measurements={"log_retention_days": retention_days},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "ephi_access_logging_enabled": True,
                "log_retention_days": retention_days,
                "log_review_frequency": config_data.get("log_review_frequency"),
            },
            evidence_refs=evidence_refs,
        )


class HIPAAIntegrityPCU(BasePCU):
    """PCU-HIPAA-INTEGRITY — 164.312(c)(1)

    Predicate P-HIPAA-312-C1:
      Implement policies and procedures to protect ePHI from improper
      alteration or destruction.
    """

    pcu_id = "PCU-HIPAA-INTEGRITY"
    version = "1.0.0"
    evaluates = ["P-HIPAA-312-C1"]
    framework = "hipaa"
    description = "Validates ePHI integrity controls"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="integrity_controls",
            source="data_management",
            type="integrity_configuration",
            required=True,
        ),
    ]

    parameters = {
        "require_integrity_verification": True,
        "require_tamper_detection": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        integrity = self.get_evidence(evidence, "integrity_configuration")

        if integrity is None:
            return self.warn("Missing integrity control configuration")

        evidence_refs = [integrity.hash or integrity.evidence_id]
        config_data = integrity.data

        if self.parameters["require_integrity_verification"]:
            if not config_data.get("integrity_verification_enabled", False):
                return self.fail(
                    "ePHI integrity verification not enabled",
                    measurements={"integrity_verification_enabled": False},
                    evidence_refs=evidence_refs,
                )

        if self.parameters["require_tamper_detection"]:
            if not config_data.get("tamper_detection_enabled", False):
                return self.fail(
                    "Tamper detection not enabled",
                    measurements={"tamper_detection_enabled": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "integrity_verification_enabled": True,
                "tamper_detection_enabled": True,
                "checksum_algorithm": config_data.get("checksum_algorithm"),
            },
            evidence_refs=evidence_refs,
        )


class HIPAAAuthenticationPCU(BasePCU):
    """PCU-HIPAA-AUTH — 164.312(d)

    Predicate P-HIPAA-312-D:
      Implement procedures to verify that a person or entity seeking
      access to ePHI is the one claimed.
    """

    pcu_id = "PCU-HIPAA-AUTH"
    version = "1.0.0"
    evaluates = ["P-HIPAA-312-D"]
    framework = "hipaa"
    description = "Validates person/entity authentication"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="auth_config",
            source="iam_system",
            type="authentication_configuration",
            required=True,
        ),
    ]

    parameters = {
        "require_strong_authentication": True,
        "require_mfa_for_remote": True,
        "min_password_length": 12,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        auth_config = self.get_evidence(evidence, "authentication_configuration")

        if auth_config is None:
            return self.warn("Missing authentication configuration")

        evidence_refs = [auth_config.hash or auth_config.evidence_id]
        config_data = auth_config.data

        if self.parameters["require_strong_authentication"]:
            min_length = config_data.get("min_password_length", 0)
            if min_length < self.parameters["min_password_length"]:
                return self.fail(
                    f"Minimum password length {min_length} below required "
                    f"{self.parameters['min_password_length']}",
                    measurements={"min_password_length": min_length},
                    evidence_refs=evidence_refs,
                )

        if self.parameters["require_mfa_for_remote"]:
            if not config_data.get("mfa_remote_access", False):
                return self.fail(
                    "MFA not required for remote access",
                    measurements={"mfa_remote_access": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "min_password_length": config_data.get("min_password_length"),
                "mfa_remote_access": config_data.get("mfa_remote_access"),
                "mfa_all_users": config_data.get("mfa_all_users", False),
            },
            evidence_refs=evidence_refs,
        )


class HIPAATransmissionSecurityPCU(BasePCU):
    """PCU-HIPAA-TRANSMISSION — 164.312(e)(1)

    Predicate P-HIPAA-312-E1:
      Implement technical security measures to guard against unauthorized
      access to ePHI that is being transmitted over an electronic
      communications network.
    """

    pcu_id = "PCU-HIPAA-TRANSMISSION"
    version = "1.0.0"
    evaluates = ["P-HIPAA-312-E1"]
    framework = "hipaa"
    description = "Validates ePHI transmission security"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="transmission_config",
            source="network_security",
            type="transmission_security_configuration",
            required=True,
        ),
    ]

    parameters = {
        "require_encryption_in_transit": True,
        "min_tls_version": "1.2",
        "require_integrity_controls": True,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        trans_config = self.get_evidence(evidence, "transmission_security_configuration")

        if trans_config is None:
            return self.warn("Missing transmission security configuration")

        evidence_refs = [trans_config.hash or trans_config.evidence_id]
        config_data = trans_config.data

        if self.parameters["require_encryption_in_transit"]:
            if not config_data.get("encryption_in_transit", False):
                return self.fail(
                    "Encryption not enabled for ePHI transmission",
                    measurements={"encryption_in_transit": False},
                    evidence_refs=evidence_refs,
                )

        # Check TLS version
        tls_version = config_data.get("tls_version", "")
        version_map = {"1.0": 1.0, "1.1": 1.1, "1.2": 1.2, "1.3": 1.3}
        min_required = version_map.get(self.parameters["min_tls_version"], 1.2)
        actual = version_map.get(tls_version, 0)

        if actual < min_required:
            return self.fail(
                f"TLS version {tls_version} below minimum {self.parameters['min_tls_version']}",
                measurements={"tls_version": tls_version},
                evidence_refs=evidence_refs,
            )

        if self.parameters["require_integrity_controls"]:
            if not config_data.get("integrity_controls_enabled", False):
                return self.fail(
                    "Transmission integrity controls not enabled",
                    measurements={"integrity_controls_enabled": False},
                    evidence_refs=evidence_refs,
                )

        return self.pass_result(
            measurements={
                "encryption_in_transit": True,
                "tls_version": tls_version,
                "integrity_controls_enabled": True,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 164.316 — POLICIES AND PROCEDURES
# ═══════════════════════════════════════════════════════════════════════════════


class HIPAAPoliciesDocumentationPCU(BasePCU):
    """PCU-HIPAA-POLICIES — 164.316(a) & (b)

    Predicate P-HIPAA-316:
      Implement reasonable and appropriate policies and procedures to
      comply with the standards, implementation specifications, or other
      requirements. Maintain written policies and procedures and written
      documentation of actions, activities, or assessments.
    """

    pcu_id = "PCU-HIPAA-POLICIES"
    version = "1.0.0"
    evaluates = ["P-HIPAA-316"]
    framework = "hipaa"
    description = "Validates HIPAA policies and documentation requirements"
    pcu_type = PCUType.DETERMINISTIC

    evidence_inputs = [
        EvidenceSpec(
            name="policy_inventory",
            source="policy_repo",
            type="hipaa_policy_inventory",
            required=True,
        ),
    ]

    parameters = {
        "min_retention_years": 6,
        "require_all_safeguard_policies": True,
        "max_days_since_policy_review": 365,
    }

    def evaluate(
        self, artifact: Artifact, context: Context, evidence: EvidenceBundle
    ) -> PCUResult:
        """Evaluate the predicate against the provided artifact, context, and evidence.

        Returns PASS if evidence confirms the predicate is satisfied, WARN if evidence
        is absent or insufficient, and FAIL if evidence confirms a violation.
        """
        policies = self.get_evidence(evidence, "hipaa_policy_inventory")

        if policies is None:
            return self.warn("Missing HIPAA policy inventory")

        evidence_refs = [policies.hash or policies.evidence_id]
        policy_data = policies.data

        # Check required policies exist
        required_policies = [
            "security_management",
            "workforce_security",
            "access_management",
            "security_training",
            "incident_response",
            "contingency_plan",
            "device_media_controls",
            "access_control",
            "audit_controls",
            "integrity_controls",
            "transmission_security",
        ]

        existing_policies = policy_data.get("policies", [])
        existing_names = [p.get("name", "").lower() for p in existing_policies]

        missing_policies = []
        for req in required_policies:
            found = any(req in name for name in existing_names)
            if not found:
                missing_policies.append(req)

        if missing_policies and self.parameters["require_all_safeguard_policies"]:
            return self.fail(
                f"Missing required policies: {missing_policies}",
                measurements={"missing_policies": missing_policies},
                evidence_refs=evidence_refs,
            )

        # Check retention
        retention_years = policy_data.get("documentation_retention_years", 0)
        if retention_years < self.parameters["min_retention_years"]:
            return self.fail(
                f"Documentation retention {retention_years} years below "
                f"minimum {self.parameters['min_retention_years']} years",
                measurements={"retention_years": retention_years},
                evidence_refs=evidence_refs,
            )

        return self.pass_result(
            measurements={
                "total_policies": len(existing_policies),
                "missing_policies": missing_policies,
                "retention_years": retention_years,
            },
            evidence_refs=evidence_refs,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# REGISTRATION
# ═══════════════════════════════════════════════════════════════════════════════


def register_hipaa_pcus(registry: "PCURegistry") -> None:
    """Register all HIPAA PCUs with the given registry."""
    pcus = [
        # Administrative Safeguards (164.308)
        HIPAARiskAnalysisPCU(),
        HIPAASanctionPolicyPCU(),
        HIPAASecurityOfficerPCU(),
        HIPAAWorkforceSecurityPCU(),
        HIPAASecurityTrainingPCU(),
        HIPAAIncidentProceduresPCU(),
        HIPAAContingencyPlanPCU(),
        HIPAAEvaluationPCU(),
        # Physical Safeguards (164.310)
        HIPAAFacilityAccessPCU(),
        HIPAAWorkstationSecurityPCU(),
        HIPAADeviceMediaControlsPCU(),
        # Technical Safeguards (164.312)
        HIPAAAccessControlPCU(),
        HIPAAAuditControlsPCU(),
        HIPAAIntegrityPCU(),
        HIPAAAuthenticationPCU(),
        HIPAATransmissionSecurityPCU(),
        # Policies (164.316)
        HIPAAPoliciesDocumentationPCU(),
    ]

    for pcu in pcus:
        registry.register(pcu)

    # Register predicate→gate mappings
    gate_mappings = {
        # Administrative - Risk (G4)
        "P-HIPAA-308-A1-R": "G4",
        # Administrative - Policies (G1)
        "P-HIPAA-308-A1-S": "G1",
        # Administrative - Oversight (G7)
        "P-HIPAA-308-A2": "G7",
        "P-HIPAA-308-A5": "G7",
        # Administrative - Security (G2)
        "P-HIPAA-308-A3": "G2",
        "P-HIPAA-308-A6": "G2",
        "P-HIPAA-308-A7": "G2",
        # Administrative - Monitoring (G8)
        "P-HIPAA-308-A8": "G8",
        # Physical - Security (G2)
        "P-HIPAA-310-A1": "G2",
        "P-HIPAA-310-B1": "G2",
        # Physical - Data Governance (G3)
        "P-HIPAA-310-D1": "G3",
        # Technical - Security (G2)
        "P-HIPAA-312-A1": "G2",
        "P-HIPAA-312-C1": "G2",
        "P-HIPAA-312-D": "G2",
        "P-HIPAA-312-E1": "G2",
        # Technical - Audit (G6)
        "P-HIPAA-312-B": "G6",
        # Policies (G1)
        "P-HIPAA-316": "G1",
    }

    for pred_id, gate_id in gate_mappings.items():
        registry.register_predicate_gate_mapping(pred_id, gate_id)
        gate = registry.get_gate(gate_id)
        if gate and pred_id not in gate.predicate_ids:
            gate.predicate_ids.append(pred_id)

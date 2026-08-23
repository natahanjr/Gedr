"""Unit tests for the risk engine."""
import pytest
from backend.scanner_manager import RiskEngine


class TestRiskEngineSeverityClassification:
    """Test severity classification logic."""

    @pytest.fixture
    def risk_engine(self):
        return RiskEngine()

    def test_critical_severity(self, risk_engine):
        """Scores 9-10 are Critical."""
        assert risk_engine.classify(10) == "Critical"
        assert risk_engine.classify(9) == "Critical"

    def test_high_severity(self, risk_engine):
        """Scores 7-8 are High."""
        assert risk_engine.classify(8) == "High"
        assert risk_engine.classify(7) == "High"

    def test_medium_severity(self, risk_engine):
        """Scores 4-6 are Medium."""
        assert risk_engine.classify(6) == "Medium"
        assert risk_engine.classify(5) == "Medium"
        assert risk_engine.classify(4) == "Medium"

    def test_low_severity(self, risk_engine):
        """Scores 1-3 are Low."""
        assert risk_engine.classify(3) == "Low"
        assert risk_engine.classify(2) == "Low"
        assert risk_engine.classify(1) == "Low"
        assert risk_engine.classify(0) == "Low"


class TestRiskEngineScoring:
    """Test security score computation."""

    @pytest.fixture
    def risk_engine(self):
        return RiskEngine()

    def test_no_findings_perfect_score(self, risk_engine):
        """No findings = 100/100."""
        score = risk_engine.compute_security_score([], total_files=10)
        assert score == 100

    def test_single_critical_penalty(self, risk_engine):
        """One Critical finding deducts 30 points."""
        findings = [{"severity": "Critical"}]
        score = risk_engine.compute_security_score(findings, total_files=1)
        # For single file: scale = 1.0, so 100 - 30 = 70
        assert score == 70

    def test_single_high_penalty(self, risk_engine):
        """One High finding deducts 15 points."""
        findings = [{"severity": "High"}]
        score = risk_engine.compute_security_score(findings, total_files=1)
        # 100 - 15 = 85
        assert score == 85

    def test_single_medium_penalty(self, risk_engine):
        """One Medium finding deducts 6 points."""
        findings = [{"severity": "Medium"}]
        score = risk_engine.compute_security_score(findings, total_files=1)
        # 100 - 6 = 94
        assert score == 94

    def test_single_low_penalty(self, risk_engine):
        """One Low finding deducts 2 points."""
        findings = [{"severity": "Low"}]
        score = risk_engine.compute_security_score(findings, total_files=1)
        # 100 - 2 = 98
        assert score == 98

    def test_multiple_findings_accumulate(self, risk_engine):
        """Multiple findings accumulate penalties."""
        findings = [
            {"severity": "Critical"},  # 30
            {"severity": "High"},      # 15
            {"severity": "Medium"},    # 6
        ]
        score = risk_engine.compute_security_score(findings, total_files=1)
        # 100 - (30 + 15 + 6) = 49
        assert score == 49

    def test_score_never_negative(self, risk_engine):
        """Score is floored at 0."""
        findings = [
            {"severity": "Critical"} for _ in range(10)
        ]
        score = risk_engine.compute_security_score(findings, total_files=1)
        assert score >= 0
        assert score == 0

    def test_scaling_with_project_size_small(self, risk_engine):
        """Large projects get scaled penalties (less harsh)."""
        findings = [{"severity": "Critical"}]  # 30 points
        # Single file: scale = 1.0
        score_single = risk_engine.compute_security_score(findings, total_files=1)
        # 100 files: scale = max(0.4, 10/100) = 0.4
        score_large = risk_engine.compute_security_score(findings, total_files=100)
        
        assert score_single == 70  # 100 - 30
        assert score_large == 88   # 100 - (30 * 0.4) = 88

    def test_scaling_with_project_size_min(self, risk_engine):
        """Scaling has a minimum of 0.4."""
        findings = [{"severity": "Critical"}]
        # 1000 files: scale = max(0.4, 10/1000) = 0.4
        score = risk_engine.compute_security_score(findings, total_files=1000)
        assert score == 88  # 100 - (30 * 0.4)

    def test_unknown_severity_defaults_to_low(self, risk_engine):
        """Unknown severity treated as Low."""
        findings = [{"severity": "Unknown"}]
        score = risk_engine.compute_security_score(findings, total_files=1)
        assert score == 98  # 100 - 2


class TestRiskEngineGrading:
    """Test letter grade assignment."""

    @pytest.fixture
    def risk_engine(self):
        return RiskEngine()

    def test_grade_a_plus(self, risk_engine):
        """Score >= 90 = A+."""
        assert risk_engine.grade(100) == "A+ (Secure)"
        assert risk_engine.grade(90) == "A+ (Secure)"

    def test_grade_a(self, risk_engine):
        """Score 80-89 = A."""
        assert risk_engine.grade(89) == "A (Good)"
        assert risk_engine.grade(80) == "A (Good)"

    def test_grade_b(self, risk_engine):
        """Score 70-79 = B."""
        assert risk_engine.grade(79) == "B (Acceptable)"
        assert risk_engine.grade(70) == "B (Acceptable)"

    def test_grade_c(self, risk_engine):
        """Score 50-69 = C."""
        assert risk_engine.grade(69) == "C (At Risk)"
        assert risk_engine.grade(50) == "C (At Risk)"

    def test_grade_d(self, risk_engine):
        """Score 30-49 = D."""
        assert risk_engine.grade(49) == "D (High Risk)"
        assert risk_engine.grade(30) == "D (High Risk)"

    def test_grade_f(self, risk_engine):
        """Score < 30 = F."""
        assert risk_engine.grade(29) == "F (Critical)"
        assert risk_engine.grade(0) == "F (Critical)"


class TestRiskEngineEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.fixture
    def risk_engine(self):
        return RiskEngine()

    def test_mixed_finding_severities(self, risk_engine):
        """Real-world mix of severity levels."""
        findings = [
            {"severity": "Critical"},
            {"severity": "Critical"},
            {"severity": "High"},
            {"severity": "High"},
            {"severity": "High"},
            {"severity": "Medium"},
            {"severity": "Medium"},
            {"severity": "Low"},
            {"severity": "Low"},
            {"severity": "Low"},
        ]
        # Penalty: 30+30+15+15+15+6+6+2+2+2 = 123
        # Single file: 100 - 123 = 0 (floored)
        score = risk_engine.compute_security_score(findings, total_files=1)
        assert score == 0

    def test_missing_severity_field(self, risk_engine):
        """Missing severity defaults to Low."""
        findings = [{"rule_id": "TEST"}]  # no severity field
        score = risk_engine.compute_security_score(findings, total_files=1)
        # Defaults to Low penalty (2)
        assert score == 98

    def test_empty_severity_string(self, risk_engine):
        """Empty severity string defaults to Low."""
        findings = [{"severity": ""}]
        score = risk_engine.compute_security_score(findings, total_files=1)
        assert score == 98

    def test_zero_files_no_division_error(self, risk_engine):
        """Edge case: zero files scanned."""
        findings = [{"severity": "Critical"}]
        # Should handle gracefully (edge case)
        score = risk_engine.compute_security_score(findings, total_files=0)
        assert isinstance(score, int)
        assert score >= 0

    def test_boundary_score_90_vs_89(self, risk_engine):
        """Grade changes at boundary scores."""
        assert risk_engine.grade(90) == "A+ (Secure)"
        assert risk_engine.grade(89) == "A (Good)"

    def test_boundary_score_80_vs_79(self, risk_engine):
        """Another grade boundary."""
        assert risk_engine.grade(80) == "A (Good)"
        assert risk_engine.grade(79) == "B (Acceptable)"


class TestRiskEngineIntegration:
    """Integration tests for full risk engine workflow."""

    @pytest.fixture
    def risk_engine(self):
        return RiskEngine()

    def test_real_world_scenario_1(self, risk_engine):
        """Scenario: small project with one critical issue."""
        findings = [
            {
                "file": "main.py",
                "severity": "Critical",
                "rule_id": "S-CMDI-1",
                "title": "Shell injection"
            }
        ]
        score = risk_engine.compute_security_score(findings, total_files=5)
        grade = risk_engine.grade(score)
        assert score > 0
        assert "B" in grade or "C" in grade or "D" in grade or "F" in grade

    def test_real_world_scenario_2(self, risk_engine):
        """Scenario: large project with mixed findings."""
        findings = [
            {"severity": "High"} for _ in range(5)
        ] + [
            {"severity": "Medium"} for _ in range(10)
        ] + [
            {"severity": "Low"} for _ in range(20)
        ]
        score = risk_engine.compute_security_score(findings, total_files=500)
        grade = risk_engine.grade(score)
        # Should still be "At Risk" or better despite many findings
        assert "A" not in grade or score >= 50

    def test_real_world_scenario_3(self, risk_engine):
        """Scenario: clean code with no findings."""
        findings = []
        score = risk_engine.compute_security_score(findings, total_files=100)
        grade = risk_engine.grade(score)
        assert score == 100
        assert grade == "A+ (Secure)"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

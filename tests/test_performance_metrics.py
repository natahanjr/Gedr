"""
Performance benchmarking and evaluation metrics for Gədr.

Collects metrics on:
  - Scan time vs. file size/count
  - Detection accuracy (precision, recall, false positives, false negatives)
  - Resource usage (memory, CPU)
  - Performance on known vulnerable code samples
"""
import time
import tempfile
import json
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Callable

from backend.scanner_manager import ScannerManager
from database.sqlite_manager import SQLiteManager


@dataclass
class BenchmarkMetrics:
    """Metrics from a single benchmark run."""
    name: str
    files_count: int
    total_bytes: int
    scan_time_seconds: float
    findings_count: int
    findings_by_severity: dict
    score: int
    throughput_files_per_sec: float
    throughput_bytes_per_sec: float

    def to_dict(self):
        return asdict(self)


@dataclass
class EvaluationMetrics:
    """Detection accuracy metrics."""
    test_name: str
    true_positives: int  # Correctly detected vulnerabilities
    false_positives: int  # Incorrectly flagged non-vulnerabilities
    true_negatives: int  # Correctly identified as safe
    false_negatives: int  # Missed vulnerabilities
    
    @property
    def precision(self) -> float:
        """Precision = TP / (TP + FP)."""
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total > 0 else 1.0
    
    @property
    def recall(self) -> float:
        """Recall = TP / (TP + FN)."""
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total > 0 else 0.0
    
    @property
    def f1_score(self) -> float:
        """F1 = 2 * (precision * recall) / (precision + recall)."""
        p = self.precision
        r = self.recall
        if p + r == 0:
            return 0.0
        return 2 * (p * r) / (p + r)
    
    @property
    def false_positive_rate(self) -> float:
        """FPR = FP / (FP + TN)."""
        total = self.false_positives + self.true_negatives
        return self.false_positives / total if total > 0 else 0.0
    
    def to_dict(self):
        return {
            "test_name": self.test_name,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "false_positive_rate": self.false_positive_rate,
        }


class PerformanceBenchmarker:
    """Benchmark scanner performance across different workloads."""

    def __init__(self, db: SQLiteManager | None = None):
        self.db = db or SQLiteManager()
        self.manager = ScannerManager(self.db)
        self.results = []

    def benchmark_scan(self, test_name: str, source_path: Path) -> BenchmarkMetrics:
        """Run a single benchmark scan and collect metrics."""
        # Collect file statistics
        files = list(source_path.rglob("*"))
        source_files = [f for f in files if f.is_file()]
        total_bytes = sum(f.stat().st_size for f in source_files)
        
        # Run scan with timing
        start_time = time.time()
        result = self.manager.scan_path(source_path, use_ai=False)
        elapsed = time.time() - start_time
        
        # Collect severity breakdown
        severity_breakdown = {}
        for finding in result["findings"]:
            sev = finding.get("severity", "Unknown")
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
        
        # Calculate metrics
        metrics = BenchmarkMetrics(
            name=test_name,
            files_count=result["files_scanned"],
            total_bytes=total_bytes,
            scan_time_seconds=elapsed,
            findings_count=len(result["findings"]),
            findings_by_severity=severity_breakdown,
            score=result["score"],
            throughput_files_per_sec=result["files_scanned"] / elapsed if elapsed > 0 else 0,
            throughput_bytes_per_sec=total_bytes / elapsed if elapsed > 0 else 0,
        )
        
        self.results.append(metrics)
        return metrics

    def benchmark_single_file_scaling(self, language: str, code_generator: Callable[[int], str]):
        """Benchmark scan time as file size increases."""
        results = []
        
        # Test with increasing file sizes: 10KB, 100KB, 500KB, 1MB
        sizes = [10 * 1024, 100 * 1024, 500 * 1024, 1024 * 1024]
        
        for size_bytes in sizes:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir)
                
                # Generate code of approximately the target size
                code = code_generator(size_bytes)
                
                ext_map = {
                    "python": ".py",
                    "java": ".java",
                    "cpp": ".cpp",
                    "web": ".js",
                }
                
                file_path = tmp_path / f"test{ext_map.get(language, '.txt')}"
                file_path.write_text(code)
                
                # Benchmark
                test_name = f"{language}_file_{size_bytes // 1024}KB"
                metrics = self.benchmark_scan(test_name, tmp_path)
                results.append(metrics)
        
        return results

    def benchmark_directory_scaling(self, language: str, file_generator: Callable[[], str], num_files_list: list[int]):
        """Benchmark scan time as number of files increases."""
        results = []
        
        for num_files in num_files_list:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir)
                
                # Create multiple files
                ext_map = {
                    "python": ".py",
                    "java": ".java",
                    "cpp": ".cpp",
                    "web": ".js",
                }
                
                for i in range(num_files):
                    code = file_generator()
                    file_path = tmp_path / f"file_{i}{ext_map.get(language, '.txt')}"
                    file_path.write_text(code)
                
                # Benchmark
                test_name = f"{language}_directory_{num_files}_files"
                metrics = self.benchmark_scan(test_name, tmp_path)
                results.append(metrics)
        
        return results

    def export_results(self, output_path: Path):
        """Export benchmark results to JSON."""
        data = {
            "benchmarks": [m.to_dict() for m in self.results],
        }
        
        output_path.write_text(json.dumps(data, indent=2))


class EvaluationMetricsCollector:
    """Collect detection accuracy metrics against known vulnerabilities."""

    def __init__(self, db: SQLiteManager | None = None):
        self.db = db or SQLiteManager()
        self.manager = ScannerManager(self.db)
        self.results = []

    def evaluate_vulnerable_code(
        self,
        test_name: str,
        vulnerable_code: str,
        expected_findings: int,
        expected_rules: set[str],
    ) -> EvaluationMetrics:
        """Evaluate detection on known vulnerable code.
        
        Args:
            test_name: Name of this evaluation test
            vulnerable_code: Source code with known vulnerabilities
            expected_findings: Expected number of findings (approximate)
            expected_rules: Expected rule IDs that should trigger
            
        Returns:
            EvaluationMetrics with precision/recall calculations
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            
            # Write test file
            test_file = tmp_path / "vulnerable.py"  # Assuming Python for now
            test_file.write_text(vulnerable_code)
            
            # Run scan
            result = self.manager.scan_path(tmp_path, use_ai=False)
            
            # Collect actual findings
            actual_rules = {f["rule_id"] for f in result["findings"]}
            actual_count = len(result["findings"])
            
            # Calculate TP, FP, FN
            true_positives = len(expected_rules & actual_rules)
            false_positives = len(actual_rules - expected_rules)
            false_negatives = len(expected_rules - actual_rules)
            true_negatives = 0  # Not applicable for vulnerability detection
            
            metrics = EvaluationMetrics(
                test_name=test_name,
                true_positives=true_positives,
                false_positives=false_positives,
                true_negatives=true_negatives,
                false_negatives=false_negatives,
            )
            
            self.results.append(metrics)
            return metrics

    def evaluate_clean_code(self, test_name: str, clean_code: str) -> EvaluationMetrics:
        """Evaluate false positive rate on clean code.
        
        Args:
            test_name: Name of this evaluation test
            clean_code: Source code with no known vulnerabilities
            
        Returns:
            EvaluationMetrics (FP count should be 0 or minimal)
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            
            # Write test file
            test_file = tmp_path / "clean.py"
            test_file.write_text(clean_code)
            
            # Run scan
            result = self.manager.scan_path(tmp_path, use_ai=False)
            
            # All findings are false positives
            false_positives = len(result["findings"])
            
            metrics = EvaluationMetrics(
                test_name=test_name,
                true_positives=0,
                false_positives=false_positives,
                true_negatives=1,
                false_negatives=0,
            )
            
            self.results.append(metrics)
            return metrics

    def export_results(self, output_path: Path):
        """Export evaluation metrics to JSON."""
        data = {
            "evaluations": [m.to_dict() for m in self.results],
            "aggregate": self._aggregate_metrics(),
        }
        
        output_path.write_text(json.dumps(data, indent=2))

    def _aggregate_metrics(self) -> dict:
        """Calculate aggregate metrics across all tests."""
        if not self.results:
            return {}
        
        total_tp = sum(m.true_positives for m in self.results)
        total_fp = sum(m.false_positives for m in self.results)
        total_fn = sum(m.false_negatives for m in self.results)
        total_tn = sum(m.true_negatives for m in self.results)
        
        aggregate = EvaluationMetrics(
            test_name="AGGREGATE",
            true_positives=total_tp,
            false_positives=total_fp,
            true_negatives=total_tn,
            false_negatives=total_fn,
        )
        
        return aggregate.to_dict()

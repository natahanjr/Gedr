"""
Validation Engine for Gədr.
Calculates Precision, Recall, and F1-Score against a known benchmark dataset.
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Tuple

class BenchmarkValidator:
    def __init__(self, benchmark_dir: Path):
        self.benchmark_dir = benchmark_dir

    def calculate_metrics(self, ground_truth: List[str], predictions: List[str]) -> Dict:
        """
        Computes security metrics.
        - True Positive (TP): Predicted vulnerability that actually exists.
        - False Positive (FP): Predicted vulnerability that doesn't exist.
        - False Negative (FN): Existing vulnerability that was missed.
        """
        tp = len(set(ground_truth) & set(predictions))
        fp = len(set(predictions) - set(ground_truth))
        fn = len(set(ground_truth) - set(predictions))

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        return {
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "f1_score": round(f1 * 100, 2),
            "tp": tp,
            "fp": fp,
            "fn": fn
        }

    def run_full_evaluation(self, scanner_manager):
        """
        Scans benchmark files and compares findings with known labels.
        """
        all_metrics = {}
        benchmark_files = list(self.benchmark_dir.glob("**/*.*"))
        
        for file in benchmark_files:
            # 1. Run the actual scan
            result = scanner_manager.scan_path(file, use_ai=False)
            predictions = [f["rule_id"] for f in result["findings"]]
            
            # 2. Load ground truth (assumes .label file exists for each source file)
            label_file = file.with_suffix(file.suffix + ".label")
            if not label_file.exists():
                continue
                
            with open(label_file, 'r') as f:
                ground_truth = [line.strip() for line in f if line.strip()]
            
            # 3. Calculate for this specific file
            all_metrics[file.name] = self.calculate_metrics(ground_truth, predictions)
            
        return all_metrics

    def summarize(self, metrics: Dict) -> Dict:
        """Aggregates per-file metrics into a global report."""
        total_tp = sum(m["tp"] for m in metrics.values())
        total_fp = sum(m["fp"] for m in metrics.values())
        total_fn = sum(m["fn"] for m in metrics.values())
        
        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        
        return {
            "global_precision": round(precision * 100, 2),
            "global_recall": round(recall * 100, 2),
            "total_findings": total_tp + total_fp,
            "missed_vulnerabilities": total_fn
        }

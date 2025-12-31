#!/usr/bin/env python3
"""
SDDA Demo - Secret Drift Detection Algorithm Example
Demonstrates how to use the SDDA engine to detect drift in secret usage.
"""

import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from engines.sdda import (
    PipelineRun,
    SecretUsage,
    run_sdda,
    rebuild_baselines,
    analyze_secret
)

def generate_historical_data(db_path="demo_sdda.db"):
    """Generate synthetic historical data to establish baselines"""
    print("📊 Generating historical pipeline data...")
    
    # Simulate 40 pipeline runs over 30 days
    base_date = datetime.now() - timedelta(days=30)
    
    historical_runs = []
    for i in range(40):
        run_date = base_date + timedelta(days=i * 0.75)  # ~1.3 runs per day
        
        run = PipelineRun(
            run_id=f"run-{i+1:03d}",
            timestamp=run_date,
            branch="main" if i % 5 != 4 else "develop",
            environment="staging" if i % 3 == 0 else "development",
            actor="github-actions-bot",
            secrets_used=["DB_PASSWORD", "API_KEY"],
            stages=["build", "test"]
        )
        
        # Secret usage for DB_PASSWORD
        db_usage = SecretUsage(
            secret_id="DB_PASSWORD",
            run_id=run.run_id,
            timestamp=run.timestamp,
            stages={"build", "test"},
            access_count=2,
            actor="github-actions-bot",
            environment=run.environment,
            branch=run.branch
        )
        
        # Secret usage for API_KEY
        api_usage = SecretUsage(
            secret_id="API_KEY",
            run_id=run.run_id,
            timestamp=run.timestamp,
            stages={"test"},
            access_count=1,
            actor="github-actions-bot",
            environment=run.environment,
            branch=run.branch
        )
        
        # Store historical data
        report = run_sdda(run, [db_usage, api_usage], db_path=db_path)
        
        if i % 10 == 9:
            print(f"  ✓ Generated {i+1}/40 runs")
    
    print(f"✅ Generated 40 historical runs\n")

def demonstrate_normal_run(db_path="demo_sdda.db"):
    """Demonstrate a normal pipeline run (no drift)"""
    print("🟢 Simulating NORMAL pipeline run...")
    
    run = PipelineRun(
        run_id="run-current-001",
        timestamp=datetime.now(),
        branch="main",
        environment="staging",
        actor="github-actions-bot",
        secrets_used=["DB_PASSWORD"],
        stages=["build", "test"]
    )
    
    usage = SecretUsage(
        secret_id="DB_PASSWORD",
        run_id=run.run_id,
        timestamp=run.timestamp,
        stages={"build", "test"},
        access_count=2,
        actor="github-actions-bot",
        environment="staging",
        branch="main"
    )
    
    report = run_sdda(run, [usage], db_path=db_path)
    
    print(f"  Run ID: {report.run_id}")
    print(f"  Secrets analyzed: {report.total_secrets_analyzed}")
    print(f"  Drifts detected: {len(report.drifted_secrets)}")
    print(f"  Baseline status: {report.baseline_status}")
    print(f"  Severity summary: {report.summary}\n")

def demonstrate_stage_drift(db_path="demo_sdda.db"):
    """Demonstrate drift due to new pipeline stage accessing secret"""
    print("⚠️  Simulating STAGE DRIFT (new stage accessing secret)...")
    
    run = PipelineRun(
        run_id="run-current-002",
        timestamp=datetime.now(),
        branch="main",
        environment="staging",
        actor="github-actions-bot",
        secrets_used=["DB_PASSWORD"],
        stages=["build", "test", "deploy"]  # deploy is new!
    )
    
    usage = SecretUsage(
        secret_id="DB_PASSWORD",
        run_id=run.run_id,
        timestamp=run.timestamp,
        stages={"build", "test", "deploy"},  # NEW STAGE
        access_count=3,
        actor="github-actions-bot",
        environment="staging",
        branch="main"
    )
    
    report = run_sdda(run, [usage], db_path=db_path)
    
    print(f"  Run ID: {report.run_id}")
    print(f"  Drifts detected: {len(report.drifted_secrets)}")
    
    if report.drifted_secrets:
        drift = report.drifted_secrets[0]
        print(f"  Severity: {drift.severity}")
        print(f"  Anomalies:")
        for detail in drift.anomaly_details:
            print(f"    - {detail}")
        print(f"  Recommendation: {drift.recommendation}\n")

def demonstrate_frequency_spike(db_path="demo_sdda.db"):
    """Demonstrate drift due to unusual access frequency"""
    print("⚠️  Simulating FREQUENCY SPIKE (unusual access count)...")
    
    run = PipelineRun(
        run_id="run-current-003",
        timestamp=datetime.now(),
        branch="main",
        environment="staging",
        actor="github-actions-bot",
        secrets_used=["DB_PASSWORD"],
        stages=["build", "test"]
    )
    
    usage = SecretUsage(
        secret_id="DB_PASSWORD",
        run_id=run.run_id,
        timestamp=run.timestamp,
        stages={"build", "test"},
        access_count=25,  # SPIKE! Normal is ~2
        actor="github-actions-bot",
        environment="staging",
        branch="main"
    )
    
    report = run_sdda(run, [usage], db_path=db_path)
    
    print(f"  Run ID: {report.run_id}")
    print(f"  Drifts detected: {len(report.drifted_secrets)}")
    
    if report.drifted_secrets:
        drift = report.drifted_secrets[0]
        print(f"  Severity: {drift.severity}")
        print(f"  Total drift score: {drift.total_drift_score:.2f}")
        print(f"  Frequency Z-score: {drift.frequency_drift.z_score:.2f}")
        print(f"  Anomalies:")
        for detail in drift.anomaly_details:
            print(f"    - {detail}")
        print(f"  Recommendation: {drift.recommendation}\n")

def demonstrate_new_actor(db_path="demo_sdda.db"):
    """Demonstrate drift due to new actor accessing secret"""
    print("⚠️  Simulating NEW ACTOR drift...")
    
    run = PipelineRun(
        run_id="run-current-004",
        timestamp=datetime.now(),
        branch="feature/new-api",
        environment="staging",
        actor="john.doe@company.com",  # NEW ACTOR!
        secrets_used=["DB_PASSWORD"],
        stages=["build", "test"]
    )
    
    usage = SecretUsage(
        secret_id="DB_PASSWORD",
        run_id=run.run_id,
        timestamp=run.timestamp,
        stages={"build", "test"},
        access_count=2,
        actor="john.doe@company.com",  # NEW
        environment="staging",
        branch="feature/new-api"
    )
    
    report = run_sdda(run, [usage], db_path=db_path)
    
    print(f"  Run ID: {report.run_id}")
    print(f"  Drifts detected: {len(report.drifted_secrets)}")
    
    if report.drifted_secrets:
        drift = report.drifted_secrets[0]
        print(f"  Severity: {drift.severity}")
        print(f"  Actor drift: {drift.actor_drift.is_anomaly}")
        print(f"  Anomalies:")
        for detail in drift.anomaly_details:
            print(f"    - {detail}")
        print(f"  Recommendation: {drift.recommendation}\n")

def demonstrate_production_drift(db_path="demo_sdda.db"):
    """Demonstrate CRITICAL drift due to production environment"""
    print("🚨 Simulating PRODUCTION ENVIRONMENT drift (CRITICAL)...")
    
    run = PipelineRun(
        run_id="run-current-005",
        timestamp=datetime.now(),
        branch="main",
        environment="production",  # PRODUCTION!
        actor="github-actions-bot",
        secrets_used=["DB_PASSWORD"],
        stages=["build", "test", "deploy"]
    )
    
    usage = SecretUsage(
        secret_id="DB_PASSWORD",
        run_id=run.run_id,
        timestamp=run.timestamp,
        stages={"build", "test", "deploy"},
        access_count=3,
        actor="github-actions-bot",
        environment="production",  # CRITICAL!
        branch="main"
    )
    
    report = run_sdda(run, [usage], db_path=db_path)
    
    print(f"  Run ID: {report.run_id}")
    print(f"  Drifts detected: {len(report.drifted_secrets)}")
    
    if report.drifted_secrets:
        drift = report.drifted_secrets[0]
        print(f"  Severity: {drift.severity}")
        print(f"  Environment drift Z-score: {drift.environment_drift.z_score:.2f}")
        print(f"  Anomalies:")
        for detail in drift.anomaly_details:
            print(f"    - {detail}")
        print(f"  Recommendation: {drift.recommendation}\n")

def demonstrate_secret_analysis(db_path="demo_sdda.db"):
    """Demonstrate analyzing a specific secret's behavior"""
    print("📈 Analyzing secret: DB_PASSWORD")
    
    analysis = analyze_secret("DB_PASSWORD", db_path=db_path)
    
    print(f"  Secret ID: {analysis['secret_id']}")
    print(f"  Total runs: {analysis['total_runs']}")
    print(f"  Time window: {analysis['time_window_days']} days")
    print(f"  Behavioral Features:")
    print(f"    Stages: {analysis['behavioral_features']['stages']}")
    print(f"    Actors: {analysis['behavioral_features']['actors']}")
    print(f"    Environments: {analysis['behavioral_features']['environments']}")
    print(f"    Avg accesses/run: {analysis['behavioral_features']['avg_accesses_per_run']:.2f}")
    
    if analysis['baseline']:
        print(f"  Baseline Statistics:")
        print(f"    Stage mean: {analysis['baseline']['stage_mean']:.2f} ± {analysis['baseline']['stage_std']:.2f}")
        print(f"    Access mean: {analysis['baseline']['access_mean']:.2f} ± {analysis['baseline']['access_std']:.2f}")
        print(f"    Sample count: {analysis['baseline']['sample_count']}")
        print(f"    Last updated: {analysis['baseline']['updated_at']}")
    print()

def main():
    """Run complete SDDA demonstration"""
    print("=" * 70)
    print("  SDDA - Secret Drift Detection Algorithm Demo")
    print("=" * 70)
    print()
    
    # Clean up previous demo database
    db_path = "demo_sdda.db"
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"🗑️  Removed old demo database\n")
    
    # Step 1: Generate historical data
    generate_historical_data(db_path)
    
    # Step 2: Rebuild baselines
    print("🔄 Building baselines from historical data...")
    count = rebuild_baselines(db_path=db_path)
    print(f"✅ Built {count} baselines\n")
    
    # Step 3: Analyze a secret
    demonstrate_secret_analysis(db_path)
    
    # Step 4: Demonstrate various scenarios
    demonstrate_normal_run(db_path)
    demonstrate_stage_drift(db_path)
    demonstrate_frequency_spike(db_path)
    demonstrate_new_actor(db_path)
    demonstrate_production_drift(db_path)
    
    print("=" * 70)
    print("  Demo Complete!")
    print(f"  Database saved to: {db_path}")
    print("=" * 70)

if __name__ == "__main__":
    main()

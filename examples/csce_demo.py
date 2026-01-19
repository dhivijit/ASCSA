# CSCE Example - Demonstrating correlation engine
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from engines.hcrs.models import SecurityViolation, Severity, ViolationType, CodeLocation
from engines.slga.models import Secret
from engines.sdda.models import DriftDetection
from engines.csce import run_csce
from engines.csce.reporter import CSCEReporter

def create_sample_data():
    """Create sample data for demonstration"""
    
    # Sample HCRS violations
    violations = [
        SecurityViolation(
            violation_type=ViolationType.HARDCODED_SECRET,
            severity=Severity.CRITICAL,
            location=CodeLocation(
                file_path="src/config.py",
                line_start=42,
                line_end=42,
                snippet='API_KEY = "sk_live_abc123def456"'
            ),
            message="Hardcoded API key detected",
            description="API key should be stored in environment variables"
        ),
        SecurityViolation(
            violation_type=ViolationType.SENSITIVE_LOGGING,
            severity=Severity.HIGH,
            location=CodeLocation(
                file_path="src/api/auth.py",
                line_start=89,
                line_end=89,
                snippet='logger.info(f"Password: {user_password}")'
            ),
            message="Sensitive data in logs",
            description="Logging user password is a security risk"
        ),
        SecurityViolation(
            violation_type=ViolationType.COMMAND_INJECTION,
            severity=Severity.CRITICAL,
            location=CodeLocation(
                file_path="src/utils/deploy.py",
                line_start=125,
                line_end=125,
                snippet='os.system(f"deploy --key {api_key}")'
            ),
            message="Command injection vulnerability",
            description="Unsanitized input in system command"
        )
    ]
    
    # Sample SLGA secrets
    secrets = [
        Secret(
            value="sk_live_abc123def456",
            secret_type="api_key",
            entropy=4.5,
            files=["src/config.py", "src/utils/deploy.py"],
            lines=[42, 125],
            commits=["abc123", "def456"]
        ),
        Secret(
            value="super_secret_password_123",
            secret_type="password",
            entropy=4.2,
            files=["src/api/auth.py"],
            lines=[89],
            commits=["ghi789"]
        )
    ]
    
    # Sample SDDA drifts
    drifts = [
        DriftDetection(
            secret_id="sk_live_abc123def456",
            run_id="test_run_123",
            timestamp=datetime.now(),
            severity="CRITICAL",
            is_drifted=True,
            total_drift_score=999.0,
            anomaly_details=["Secret used in PRODUCTION for first time!", "New stages detected: deploy"],
            recommendation="Immediately verify authorization, rotate secret, audit logs"
        )
    ]
    
    return violations, secrets, drifts

def main():
    print("=" * 80)
    print("CSCE - Code-Secret Correlation Engine Demo")
    print("=" * 80)
    print()
    
    # Create sample data
    print("📊 Creating sample security findings...")
    violations, secrets, drifts = create_sample_data()
    
    print(f"   - {len(violations)} HCRS violations")
    print(f"   - {len(secrets)} SLGA secrets")
    print(f"   - {len(drifts)} SDDA drifts")
    print()
    
    # Run correlation
    print("🔗 Running CSCE correlation analysis...")
    report = run_csce(
        hcrs_violations=violations,
        sdda_drifts=drifts,
        slga_secrets=secrets
    )
    print()
    
    # Display results
    print("=" * 80)
    print("RESULTS")
    print("=" * 80)
    print()
    print(f"Total Correlations Found: {report.total_correlations}")
    print(f"Average Confidence: {report.avg_confidence:.1%}")
    print()
    print("Severity Breakdown:")
    print(f"  🚨 Critical: {report.critical_count}")
    print(f"  ⚠️  High:     {report.high_count}")
    print(f"  📋 Medium:   {report.medium_count}")
    print(f"  ℹ️  Low:      {report.low_count}")
    print()
    
    # Show critical correlations
    critical = report.get_critical_alerts()
    if critical:
        print("=" * 80)
        print(f"🚨 CRITICAL CORRELATIONS ({len(critical)})")
        print("=" * 80)
        for i, corr in enumerate(critical, 1):
            print()
            print(f"{i}. {corr.description}")
            print(f"   Type: {corr.correlation_type.value.upper()}")
            print(f"   Confidence: {corr.confidence:.1%}")
            print(f"   💡 {corr.recommendation}")
    
    # Show top priorities
    if report.top_priorities:
        print()
        print("=" * 80)
        print(f"📌 TOP PRIORITIES (showing {min(3, len(report.top_priorities))})")
        print("=" * 80)
        for i, corr in enumerate(report.top_priorities[:3], 1):
            severity_icon = {
                'CRITICAL': '🚨',
                'HIGH': '⚠️',
                'MEDIUM': '📋',
                'LOW': 'ℹ️'
            }.get(corr.severity.value, '•')
            
            print()
            print(f"{i}. {severity_icon} [{corr.severity.value}] {corr.description}")
            print(f"   Confidence: {corr.confidence:.1%}")
            
            if corr.evidence:
                print(f"   Evidence:")
                for key, value in list(corr.evidence.items())[:3]:
                    print(f"     - {key}: {value}")
    
    print()
    print("=" * 80)
    
    # Generate reports
    print()
    print("📄 Generating reports...")
    
    # Save text report
    text_report = CSCEReporter.generate_text_report(report)
    with open("csce_report.txt", "w", encoding='utf-8') as f:
        f.write(text_report)
    print("   ✓ Text report saved to: csce_report.txt")
    
    # Save JSON report
    CSCEReporter.save_report(report, "csce_report.json", format='json')
    print("   ✓ JSON report saved to: csce_report.json")
    
    # Summary
    print()
    summary = CSCEReporter.generate_summary(report)
    print(f"Summary: {summary}")
    
    print()
    print("=" * 80)
    print("Demo complete! Check the generated report files.")
    print("=" * 80)

if __name__ == "__main__":
    main()

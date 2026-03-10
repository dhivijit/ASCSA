"""
Synthetic SDDA Validation — RQ2

Constructs a controlled baseline of 25 seeded runs, pre-commits the baseline
to the database so the anomalous run compares against stable history (not a
contaminated re-computation), then injects a clear anomaly on each of the five
drift dimensions and asserts detection fires.

Key design decisions:
  - Uses the production default min_samples=20 (not a relaxed test value).
  - Pre-builds and stores the baseline before the anomalous run so the
    anomalous usage record is not included in baseline statistics.
  - Tests all five drift dimensions: actor, environment, frequency, stage, branch.
  - Includes a negative control (stable run) and a below-threshold control.
"""
import os
import tempfile
import unittest
from datetime import datetime, timedelta

from engines.sdda import (
    PipelineRun,
    SecretUsage,
    run_sdda,
    SDDADatabase,
    BaselineManager,
)


class TestSyntheticSDDAValidation(unittest.TestCase):
    """
    End-to-end controlled validation that the SDDA detection pipeline
    fires precisely when anomalies are injected into a stable baseline.
    """

    _N_BASELINE = 25           # > min_samples=20 (production default)
    _STABLE_ACTOR = "ci-bot"
    _STABLE_ENV = "dev"
    _STABLE_STAGES = frozenset({"build", "test"})
    _STABLE_ACCESS = 2
    _STABLE_BRANCH = "main"
    _WINDOW_DAYS = 30

    def setUp(self):
        db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self._db_path = db_file.name
        db_file.close()

    def tearDown(self):
        if os.path.exists(self._db_path):
            os.remove(self._db_path)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _seed_baseline(self, secret_id: str) -> None:
        """
        Insert _N_BASELINE stable usage records then pre-build and persist
        the baseline.  Pre-building is essential: it prevents the anomalous
        run from contaminating the baseline statistics on first detection.
        """
        base_time = datetime.now() - timedelta(days=self._N_BASELINE)
        db = SDDADatabase(self._db_path)

        for i in range(self._N_BASELINE):
            ts = base_time + timedelta(days=i)
            run = PipelineRun(
                run_id=f"baseline-{secret_id}-{i:03d}",
                timestamp=ts,
                branch=self._STABLE_BRANCH,
                environment=self._STABLE_ENV,
                actor=self._STABLE_ACTOR,
                secrets_used=[secret_id],
                stages=list(self._STABLE_STAGES),
            )
            db.store_pipeline_run(run)
            db.store_secret_usage(SecretUsage(
                secret_id=secret_id,
                run_id=run.run_id,
                timestamp=ts,
                stages=set(self._STABLE_STAGES),
                access_count=self._STABLE_ACCESS,
                actor=self._STABLE_ACTOR,
                environment=self._STABLE_ENV,
                branch=self._STABLE_BRANCH,
            ))

        # Pre-compute and store the baseline so the subsequent anomalous run
        # finds it immediately without including the anomalous data point.
        config = {
            "baseline_window_days": self._WINDOW_DAYS,
            "min_samples": 20,
        }
        manager = BaselineManager(db, config)
        manager.update_baseline(secret_id)
        db.close()

    def _run_anomalous(self, secret_id: str, **overrides):
        """
        Execute run_sdda() with a single usage built from the stable defaults
        plus any overrides.  store_report=False to avoid polluting subsequent
        baseline queries.
        """
        ts = datetime.now()
        run = PipelineRun(
            run_id=f"anomaly-{secret_id}",
            timestamp=ts,
            branch=overrides.get("branch", self._STABLE_BRANCH),
            environment=overrides.get("environment", self._STABLE_ENV),
            actor=overrides.get("actor", self._STABLE_ACTOR),
            secrets_used=[secret_id],
            stages=list(overrides.get("stages", self._STABLE_STAGES)),
        )
        usage = SecretUsage(
            secret_id=secret_id,
            run_id=run.run_id,
            timestamp=ts,
            stages=overrides.get("stages", set(self._STABLE_STAGES)),
            access_count=overrides.get("access_count", self._STABLE_ACCESS),
            actor=overrides.get("actor", self._STABLE_ACTOR),
            environment=overrides.get("environment", self._STABLE_ENV),
            branch=overrides.get("branch", self._STABLE_BRANCH),
        )
        return run_sdda(
            pipeline_run=run,
            secret_usages=[usage],
            db_path=self._db_path,
            store_report=False,
        )

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_stable_run_produces_no_drift(self):
        """
        Negative control: a run with identical parameters to the baseline
        must not trigger any drift detection.
        """
        sid = "CTRL_STABLE"
        self._seed_baseline(sid)
        report = self._run_anomalous(sid)  # all stable params
        drifted = [d for d in report.drifted_secrets if d.secret_id == sid]
        self.assertEqual(
            len(drifted), 0,
            "Stable run with identical parameters should not trigger drift",
        )
        self.assertTrue(
            report.baseline_status.startswith("OK"),
            f"Expected OK baseline_status, got: {report.baseline_status}",
        )

    def test_actor_anomaly_fires(self):
        """
        New unknown actor not in the baseline must trigger drift detection.
        This covers the actor drift dimension in comparators.compare_actors().
        """
        sid = "ACTOR_DRIFT"
        self._seed_baseline(sid)
        report = self._run_anomalous(sid, actor="unknown-intruder")
        drifted = [d for d in report.drifted_secrets if d.secret_id == sid]
        self.assertGreater(
            len(drifted), 0,
            "An unknown actor should trigger actor drift detection",
        )
        self.assertTrue(
            report.baseline_status.startswith("DRIFT_DETECTED"),
            f"Expected DRIFT_DETECTED status, got: {report.baseline_status}",
        )

    def test_production_environment_anomaly_fires_as_critical(self):
        """
        Secret used in 'production' for the first time must fire at CRITICAL.
        This covers compare_environment()'s explicit prod-misuse escalation.
        """
        sid = "ENV_PROD_DRIFT"
        self._seed_baseline(sid)
        report = self._run_anomalous(sid, environment="production")
        drifted = [d for d in report.drifted_secrets if d.secret_id == sid]
        self.assertGreater(
            len(drifted), 0,
            "Production environment (never seen before) should trigger drift",
        )
        self.assertEqual(
            drifted[0].severity,
            "CRITICAL",
            "Production environment misuse must be CRITICAL severity "
            f"(got {drifted[0].severity})",
        )

    def test_frequency_spike_anomaly_fires(self):
        """
        An access count 15× above the baseline mean exceeds the z-score
        threshold and must trigger frequency drift detection.
        """
        sid = "FREQ_SPIKE"
        self._seed_baseline(sid)
        spike_access = self._STABLE_ACCESS * 15  # z-score >> 3.0
        report = self._run_anomalous(sid, access_count=spike_access)
        drifted = [d for d in report.drifted_secrets if d.secret_id == sid]
        self.assertGreater(
            len(drifted), 0,
            f"Access count {spike_access}× (baseline mean {self._STABLE_ACCESS}) "
            "should trigger frequency drift",
        )

    def test_unexpected_stage_anomaly_fires(self):
        """
        Secret accessed from 'deploy-production', a stage never seen in the
        baseline, must trigger stage drift detection.
        """
        sid = "STAGE_NEW"
        self._seed_baseline(sid)
        anomalous_stages = set(self._STABLE_STAGES) | {"deploy-production"}
        report = self._run_anomalous(sid, stages=anomalous_stages)
        drifted = [d for d in report.drifted_secrets if d.secret_id == sid]
        self.assertGreater(
            len(drifted), 0,
            "An unexpected pipeline stage should trigger stage drift detection",
        )

    def test_unknown_branch_anomaly_fires(self):
        """
        Secret accessed from a suspicious branch never seen in the baseline
        must trigger branch drift detection.
        """
        sid = "BRANCH_NEW"
        self._seed_baseline(sid)
        report = self._run_anomalous(sid, branch="bypass-security")
        drifted = [d for d in report.drifted_secrets if d.secret_id == sid]
        self.assertGreater(
            len(drifted), 0,
            "An unexpected branch should trigger branch drift detection",
        )

    def test_below_min_samples_does_not_fire(self):
        """
        On the very first run (zero prior history) the engine must not
        establish a baseline, must produce zero drift detections, and must
        report an accumulating/no-baseline status.

        This is the canonical first-run scenario.  With no history the engine
        cannot distinguish anomalous from normal behaviour, so staying silent
        is the correct and safe response.
        """
        sid = "FIRST_RUN"
        # Fresh temp DB with no prior runs at all — simulate project's first scan

        report = self._run_anomalous(sid, actor="intruder")
        self.assertEqual(
            len(report.drifted_secrets),
            0,
            "First run with no baseline must not produce drift alerts",
        )
        self.assertTrue(
            "NO_BASELINES" in report.baseline_status
            or "ACCUMULATING" in report.baseline_status,
            f"Expected NO_BASELINES or ACCUMULATING in status, got: {report.baseline_status}",
        )


if __name__ == "__main__":
    unittest.main()

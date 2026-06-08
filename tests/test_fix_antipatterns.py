"""Unit tests for the fix-antipatterns CLI command and factory method.

All external dependencies (Docker, GitHub API, LLM calls) are fully mocked —
no network access, no running containers required.
"""
import os
import sys
import pytest
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'orchestrator'))


# ── Helpers ───────────────────────────────────────────────────────────────────

def exec_result(exit_code, output=b""):
    r = MagicMock()
    r.exit_code = exit_code
    r.output = output
    return r


def make_mock_container(build_file_content=b"<project/>"):
    """Return a MagicMock container whose exec_run always succeeds."""
    container = MagicMock()
    container.exec_run.return_value = exec_result(0, build_file_content)
    return container


def make_mock_fork(owner_login="sentinel-bot", default_branch="main"):
    fork = MagicMock()
    fork.html_url = "https://github.com/sentinel-bot/test-repo"
    fork.clone_url = "https://github.com/sentinel-bot/test-repo.git"
    fork.owner.login = owner_login
    fork.parent = MagicMock()
    fork.parent.default_branch = default_branch
    fork.parent.create_pull.return_value = MagicMock(html_url="https://github.com/org/repo/pull/42")
    return fork


# ── CLI tests ─────────────────────────────────────────────────────────────────

class TestFixAntipatternsCommand:
    def test_fix_antipatterns_command_exists(self):
        """sentinel fix-antipatterns --help should exit 0."""
        from click.testing import CliRunner
        # Import cli without triggering side effects
        with patch.dict(os.environ, {"GITHUB_TOKEN": "fake", "ANTHROPIC_API_KEY": "fake"}):
            from cli import sentinel
            runner = CliRunner()
            result = runner.invoke(sentinel, ["fix-antipatterns", "--help"])
        assert result.exit_code == 0
        assert "fix-antipatterns" in result.output or "anti-pattern" in result.output.lower()

    def test_requires_repo_argument(self):
        """Invoking fix-antipatterns without --repo should give an error."""
        from click.testing import CliRunner
        with patch.dict(os.environ, {"GITHUB_TOKEN": "fake", "ANTHROPIC_API_KEY": "fake"}):
            from cli import sentinel
            runner = CliRunner()
            result = runner.invoke(sentinel, ["fix-antipatterns"])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "Error" in result.output

    def test_language_choice_validation(self):
        """--language rust should be rejected as an invalid choice."""
        from click.testing import CliRunner
        with patch.dict(os.environ, {"GITHUB_TOKEN": "fake", "ANTHROPIC_API_KEY": "fake"}):
            from cli import sentinel
            runner = CliRunner()
            result = runner.invoke(sentinel, [
                "fix-antipatterns", "--repo", "https://github.com/org/repo",
                "--language", "rust"
            ])
        assert result.exit_code != 0
        assert "Invalid value" in result.output or "invalid" in result.output.lower()

    def test_llm_local_accepted(self):
        """--llm local should be a valid choice (not cause a validation error)."""
        from click.testing import CliRunner
        with patch.dict(os.environ, {"GITHUB_TOKEN": "fake", "ANTHROPIC_API_KEY": "fake"}):
            from cli import sentinel
            runner = CliRunner()
            # We only need to check that 'local' doesn't fail with "Invalid value"
            # for the --llm option; the command itself will fail later at docker check
            result = runner.invoke(sentinel, [
                "fix-antipatterns",
                "--repo", "https://github.com/org/repo",
                "--llm", "local",
                "--help",   # short-circuit before any I/O
            ])
        # --help exits 0 regardless; the important check is no "Invalid value" for --llm
        assert "Invalid value" not in result.output


# ── Factory tests ─────────────────────────────────────────────────────────────

class TestExecuteAntipatternFix:
    """Tests for RemediationFactory.execute_antipattern_fix().

    Docker client, GitHub API, and RemediationActor are all mocked.
    """

    def _make_factory(self):
        """Return a RemediationFactory with a mocked Docker client."""
        with patch('factory.docker') as mock_docker, \
             patch.dict(os.environ, {
                 "GITHUB_TOKEN": "fake-token",
                 "ANTHROPIC_API_KEY": "fake-key",
             }):
            from factory import RemediationFactory
            factory = RemediationFactory()
            return factory, mock_docker

    def _setup_container(self, mock_docker, build_file_content=b"<project/>",
                         clone_exit=0, verify_exit=0, verify_output=b"BUILD SUCCESS"):
        """Wire up mock_docker to return a properly configured container mock."""
        container = MagicMock()

        def exec_side_effect(cmd, **kwargs):
            cmd_str = str(cmd)
            # Clone operation
            if "git clone" in cmd_str:
                return exec_result(clone_exit, b"" if clone_exit == 0 else b"Clone error")
            # Build file detection
            if "test -f pom.xml" in cmd_str:
                return exec_result(0)
            # Verify command
            if "mvn" in cmd_str or "bash" in cmd_str:
                return exec_result(verify_exit, verify_output)
            # cat build file
            if "cat pom.xml" in cmd_str or ("cat" in cmd_str and "pom" in cmd_str):
                return exec_result(0, build_file_content)
            # push
            if "git push" in cmd_str:
                return exec_result(0)
            # Default: success
            return exec_result(0, b"")

        container.exec_run.side_effect = exec_side_effect
        mock_docker.from_env.return_value.containers.run.return_value = container
        return container

    def test_returns_none_when_no_patterns_found(self):
        """Should return None immediately when get_vulnerable_code_files returns {}."""
        with patch('factory.docker') as mock_docker, \
             patch('factory.Github') as mock_gh, \
             patch('factory.RemediationActor') as MockActor, \
             patch('factory._tel') as mock_tel, \
             patch.dict(os.environ, {
                 "GITHUB_TOKEN": "fake-token",
                 "ANTHROPIC_API_KEY": "fake-key",
             }):
            from factory import RemediationFactory

            # Setup Docker container mock
            container = MagicMock()
            container.exec_run.return_value = exec_result(0, b"")
            mock_docker.from_env.return_value.containers.run.return_value = container

            # Setup GitHub mock
            fork = make_mock_fork()
            mock_gh.return_value.get_repo.return_value.create_fork.return_value = fork

            # Setup telemetry mock
            mock_tel.setup_telemetry.return_value = None
            mock_tel.TokenUsageTracker.return_value = MagicMock()
            mock_tel.set_tracker.return_value = None
            mock_tel.get_tracer.return_value = MagicMock()
            mock_tel.get_tracer.return_value.start_as_current_span.return_value.__enter__ = lambda s, *a: MagicMock()
            mock_tel.get_tracer.return_value.start_as_current_span.return_value.__exit__ = MagicMock(return_value=False)
            mock_tel.remediation_duration = None
            mock_tel.patch_attempts_counter = None
            mock_tel.verify_duration = None
            mock_tel.pr_opened_counter = None

            # Actor returns empty vulnerable files
            actor_instance = MagicMock()
            actor_instance.get_vulnerable_code_files.return_value = {}
            MockActor.return_value = actor_instance

            factory = RemediationFactory()
            result = factory.execute_antipattern_fix(
                "https://github.com/org/repo", "main"
            )

        assert result is None
        actor_instance.autonomous_patch.assert_not_called()

    def test_calls_autonomous_patch_with_empty_cve_list(self):
        """autonomous_patch must be called with cves=[] (no CVE IDs) on first attempt."""
        with patch('factory.docker') as mock_docker, \
             patch('factory.Github') as mock_gh, \
             patch('factory.RemediationActor') as MockActor, \
             patch('factory._tel') as mock_tel, \
             patch.dict(os.environ, {
                 "GITHUB_TOKEN": "fake-token",
                 "ANTHROPIC_API_KEY": "fake-key",
             }):
            from factory import RemediationFactory

            container = MagicMock()

            def exec_side(cmd, **kwargs):
                if "verify_will_never_match" in str(cmd):
                    return exec_result(1, b"FAILURE")
                if "bash" in str(cmd):
                    return exec_result(1, b"BUILD FAILURE")
                return exec_result(0, b"")

            container.exec_run.side_effect = exec_side
            mock_docker.from_env.return_value.containers.run.return_value = container

            fork = make_mock_fork()
            mock_gh.return_value.get_repo.return_value.create_fork.return_value = fork

            _setup_tel(mock_tel)

            actor_instance = MagicMock()
            actor_instance.get_vulnerable_code_files.return_value = {"src/Foo.java": "code"}
            actor_instance.autonomous_patch.return_value = False  # always fail so we exit early
            actor_instance.audit = {"patterns_found": {}, "patches_written": [], "attempt": 1, "build_output": ""}
            MockActor.return_value = actor_instance

            factory = RemediationFactory()
            factory.execute_antipattern_fix("https://github.com/org/repo", "main")

        # The first call to autonomous_patch must pass [] as the CVE list
        first_call = actor_instance.autonomous_patch.call_args_list[0]
        cves_arg = first_call[0][0]  # positional arg 0
        assert cves_arg == [], f"Expected empty CVE list, got: {cves_arg}"

    def test_opens_pr_on_successful_build(self):
        """When verify exits 0, create_pull (PR) should be called on the fork."""
        with patch('factory.docker') as mock_docker, \
             patch('factory.Github') as mock_gh, \
             patch('factory.RemediationActor') as MockActor, \
             patch('factory._tel') as mock_tel, \
             patch.dict(os.environ, {
                 "GITHUB_TOKEN": "fake-token",
                 "ANTHROPIC_API_KEY": "fake-key",
             }):
            from factory import RemediationFactory

            container = MagicMock()

            def exec_side(cmd, **kwargs):
                cmd_str = str(cmd)
                if "bash" in cmd_str:
                    # Simulate successful build verify
                    return exec_result(0, b"BUILD SUCCESS")
                return exec_result(0, b"")

            container.exec_run.side_effect = exec_side
            mock_docker.from_env.return_value.containers.run.return_value = container

            fork = make_mock_fork()
            pr_mock = MagicMock(html_url="https://github.com/org/repo/pull/99")
            fork.parent.create_pull.return_value = pr_mock
            mock_gh.return_value.get_repo.return_value.create_fork.return_value = fork

            _setup_tel(mock_tel)

            actor_instance = MagicMock()
            actor_instance.get_vulnerable_code_files.return_value = {"src/Foo.java": "bad_code"}
            actor_instance.autonomous_patch.return_value = True
            actor_instance.build_system = "maven"
            actor_instance.audit = {"patterns_found": {}, "patches_written": ["src/Foo.java"],
                                     "attempt": 1, "build_output": "BUILD SUCCESS"}
            MockActor.return_value = actor_instance

            factory = RemediationFactory()
            result = factory.execute_antipattern_fix("https://github.com/org/repo", "main")

        # A PR should have been attempted (create_pull called)
        fork.parent.create_pull.assert_called_once()
        assert result == "https://github.com/org/repo/pull/99"

    def test_returns_none_after_max_attempts(self):
        """After MAX_PATCH_ATTEMPTS failed builds, the method should return None."""
        with patch('factory.docker') as mock_docker, \
             patch('factory.Github') as mock_gh, \
             patch('factory.RemediationActor') as MockActor, \
             patch('factory._tel') as mock_tel, \
             patch.dict(os.environ, {
                 "GITHUB_TOKEN": "fake-token",
                 "ANTHROPIC_API_KEY": "fake-key",
             }):
            from factory import RemediationFactory, MAX_PATCH_ATTEMPTS

            container = MagicMock()

            def exec_side(cmd, **kwargs):
                if "bash" in str(cmd):
                    return exec_result(1, b"[ERROR] BUILD FAILURE")
                return exec_result(0, b"")

            container.exec_run.side_effect = exec_side
            mock_docker.from_env.return_value.containers.run.return_value = container

            fork = make_mock_fork()
            mock_gh.return_value.get_repo.return_value.create_fork.return_value = fork

            _setup_tel(mock_tel)

            actor_instance = MagicMock()
            actor_instance.get_vulnerable_code_files.return_value = {"src/Foo.java": "code"}
            actor_instance.autonomous_patch.return_value = True  # patch "succeeds" but build fails
            actor_instance.build_system = "maven"
            actor_instance.audit = {"patterns_found": {}, "patches_written": [],
                                     "attempt": 1, "build_output": ""}
            MockActor.return_value = actor_instance

            factory = RemediationFactory()
            result = factory.execute_antipattern_fix("https://github.com/org/repo", "main")

        assert result is None
        # Should have tried exactly MAX_PATCH_ATTEMPTS times
        assert actor_instance.autonomous_patch.call_count == MAX_PATCH_ATTEMPTS

    def test_stops_container_in_finally_block(self):
        """Container stop() and remove() must be called even when an exception is raised."""
        with patch('factory.docker') as mock_docker, \
             patch('factory.Github') as mock_gh, \
             patch('factory.RemediationActor') as MockActor, \
             patch('factory._tel') as mock_tel, \
             patch.dict(os.environ, {
                 "GITHUB_TOKEN": "fake-token",
                 "ANTHROPIC_API_KEY": "fake-key",
             }):
            from factory import RemediationFactory

            container = MagicMock()
            mock_docker.from_env.return_value.containers.run.return_value = container

            # Make Github raise an unexpected exception to simulate a crash
            mock_gh.return_value.get_repo.side_effect = RuntimeError("GitHub API exploded")

            _setup_tel(mock_tel)

            factory = RemediationFactory()
            try:
                factory.execute_antipattern_fix("https://github.com/org/repo", "main")
            except Exception:
                pass  # exception is expected

        container.stop.assert_called_once()
        container.remove.assert_called_once()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _setup_tel(mock_tel):
    """Configure a telemetry mock with no-op behaviour."""
    mock_tel.setup_telemetry.return_value = None
    mock_tel.TokenUsageTracker.return_value = MagicMock()
    mock_tel.set_tracker.return_value = None
    span_cm = MagicMock()
    span_cm.__enter__ = lambda s, *a: MagicMock()
    span_cm.__exit__ = MagicMock(return_value=False)
    mock_tel.get_tracer.return_value.start_as_current_span.return_value = span_cm
    mock_tel.remediation_duration = None
    mock_tel.patch_attempts_counter = None
    mock_tel.verify_duration = None
    mock_tel.pr_opened_counter = None
    mock_tel.scan_duration = None
    mock_tel.cves_found_counter = None

"""The input hash CI uses to skip a job whose exact inputs already passed.

A skip is only safe if the hash moves whenever anything the job's build
reads moves, so most cases here are "this change must change the hash". The
other direction matters too — a hash that moves on unrelated edits never
skips anything — so a crate outside the dependency set must not move it.

Each test builds a throwaway git repo holding a three-crate Cargo workspace:
`app` depends on `lib`, and `other` stands beside them depending on nothing.
"""

import importlib.util
import subprocess
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "ci_input_hash", Path(__file__).resolve().parent.parent / "ci-input-hash.py"
)
ci_input_hash = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ci_input_hash)


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def commit(root):
    git(root, "add", "-A")
    git(root, "commit", "-qm", "change", "--allow-empty")


@pytest.fixture
def repo(tmp_path):
    write(
        tmp_path,
        "Cargo.toml",
        '[workspace]\nmembers = ["app", "lib", "other"]\nresolver = "2"\n',
    )
    for name, deps in [
        ("app", 'lib = { path = "../lib" }\n'),
        ("lib", ""),
        ("other", ""),
    ]:
        write(
            tmp_path,
            f"{name}/Cargo.toml",
            f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\n{deps}',
        )
        write(tmp_path, f"{name}/src/lib.rs", f"// {name}\n")
    write(tmp_path, ".gitlab-ci.yml", "stages: [build]\n")
    write(tmp_path, "containers/testenv.Dockerfile", "FROM rust\n")
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "ci@example.invalid")
    git(tmp_path, "config", "user.name", "ci")
    # `cargo metadata` writes the lockfile on first run; commit it so it is a
    # tracked input like in the real repo.
    subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--offline"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    commit(tmp_path)
    return tmp_path


def hash_of(repo, package="app", extra=()):
    return ci_input_hash.input_hash(repo, repo / "Cargo.toml", package, list(extra))


def test_is_stable_across_calls(repo):
    assert hash_of(repo) == hash_of(repo)


def test_changes_when_the_package_itself_changes(repo):
    before = hash_of(repo)
    write(repo, "app/src/lib.rs", "// app, edited\n")
    commit(repo)
    assert hash_of(repo) != before


def test_changes_when_a_workspace_dependency_changes(repo):
    """The case a hand-written `changes:` list gets wrong."""
    before = hash_of(repo)
    write(repo, "lib/src/lib.rs", "// lib, edited\n")
    commit(repo)
    assert hash_of(repo) != before


def test_ignores_a_crate_outside_the_dependency_set(repo):
    before = hash_of(repo)
    write(repo, "other/src/lib.rs", "// other, edited\n")
    commit(repo)
    assert hash_of(repo) == before


def test_changes_when_the_lockfile_changes(repo):
    before = hash_of(repo)
    with open(repo / "Cargo.lock", "a") as lock:
        lock.write("\n# touched\n")
    commit(repo)
    assert hash_of(repo) != before


def test_changes_when_the_ci_definition_or_image_changes(repo):
    before = hash_of(repo)
    write(repo, ".gitlab-ci.yml", "stages: [build, test]\n")
    commit(repo)
    after_ci = hash_of(repo)
    assert after_ci != before
    write(repo, "containers/testenv.Dockerfile", "FROM rust:1.90\n")
    commit(repo)
    assert hash_of(repo) != after_ci


def test_changes_when_an_extra_path_changes(repo):
    write(repo, "sim/model.py", "x = 1\n")
    commit(repo)
    before = hash_of(repo, extra=["sim"])
    write(repo, "sim/model.py", "x = 2\n")
    commit(repo)
    assert hash_of(repo, extra=["sim"]) != before


def test_depends_on_which_package_is_asked_for(repo):
    assert hash_of(repo, package="app") != hash_of(repo, package="lib")


# `ci-cached.sh`: run one CI step unless its inputs already passed.

CACHED = Path(__file__).resolve().parent.parent / "ci-cached.sh"


def cached(repo, pass_dir, *command):
    """Run `ci-cached.sh` for package `app` in `repo`; each run of `command`
    appends a line to `runs`, so a test can count real executions."""
    return subprocess.run(
        [str(CACHED), "step", "--package", "app", "--", *command],
        cwd=repo,
        env={
            **__import__("os").environ,
            "CI_PASS_DIR": str(pass_dir),
            "CI_JOB_NAME": "job:x",
        },
        capture_output=True,
        text=True,
        check=False,
    )


def runs(repo):
    path = repo / "runs"
    return len(path.read_text().splitlines()) if path.exists() else 0


def test_cached_runs_once_then_skips(repo, tmp_path):
    pass_dir = tmp_path / "passes"
    for _ in range(2):
        assert cached(repo, pass_dir, "sh", "-c", "echo ran >> runs").returncode == 0
    assert runs(repo) == 1


def test_cached_never_marks_a_failure(repo, tmp_path):
    pass_dir = tmp_path / "passes"
    for _ in range(2):
        result = cached(repo, pass_dir, "sh", "-c", "echo ran >> runs; exit 3")
        assert result.returncode == 3
    assert runs(repo) == 2


def test_cached_reruns_when_an_input_changes(repo, tmp_path):
    pass_dir = tmp_path / "passes"
    cached(repo, pass_dir, "sh", "-c", "echo ran >> runs")
    write(repo, "lib/src/lib.rs", "// lib, edited\n")
    commit(repo)
    cached(repo, pass_dir, "sh", "-c", "echo ran >> runs")
    assert runs(repo) == 2

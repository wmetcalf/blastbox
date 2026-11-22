"""The existing Loadout feed extension survives release upgrades without writable binds."""
from pathlib import Path
import pytest
from blastbox.host.cli import _parse_engine_specs
from blastbox.host.runtime.docker import RuntimeSelection, build_worker_docker_run_argv


def test_feed_mounts_come_from_operator_config(monkeypatch):
    monkeypatch.setenv('BLASTBOX_ENGINE_CLAMAV_MOUNTS', '/srv/feeds/clamav:/feeds/clamav')
    engine = _parse_engine_specs('clamav=worker:tag')['clamav']
    assert engine.mounts == (('/srv/feeds/clamav', '/feeds/clamav'),)


@pytest.mark.parametrize('value', ['relative:/feeds', '/srv:relative', '/srv:/feeds:rw', '/srv,readonly=0:/feeds', '/srv:/feeds\x00', '/srv:/feeds\n'])
def test_invalid_mount_config_fails_closed(value):
    from blastbox.host.cli import _parse_operator_mounts
    with pytest.raises(ValueError, match='mount'):
        _parse_operator_mounts(value)


def test_feed_mount_is_a_single_readonly_argument():
    argv = build_worker_docker_run_argv(image='worker:tag',input_path=Path('/jobs/input'),
        input_mount_path='/input/sample',output_dir=Path('/jobs/out'),output_mount_path='/output',
        worker_argv=[],runtime=RuntimeSelection(runtime='runsc',secure=True,warnings=[]),
        extra_mounts=(('/srv/feeds','/feeds'),))
    assert 'type=bind,src=/srv/feeds,dst=/feeds,readonly' in argv
    assert '--network=none' in argv
    assert '--read-only' in argv


@pytest.mark.parametrize('tier', ['firecracker', 'gvisor', 'static', 'aws-ec2'])
def test_operator_mounts_refuse_unsupported_warm_tiers(tier):
    from blastbox.host.dispatch import EngineSpec, enforce_allowed_runtimes
    engine = EngineSpec('clamav', 'worker:tag', [], mounts=(('/srv/feeds', '/feeds'),))
    enforce_allowed_runtimes({'clamav': engine}, {'cold'})
    with pytest.raises(ValueError, match='mount'):
        enforce_allowed_runtimes({'clamav': engine}, {'cold', tier})

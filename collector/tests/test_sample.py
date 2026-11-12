"""SMP-1 (spec 09): the sample rebuilds to the same files, so samples/ changes only when its content does."""

import subprocess
import sys
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parents[1]
SAMPLES = COLLECTOR.parent / "samples"


def test_SMP_1_sample_rebuild_matches_committed_files(tmp_path):
    # A fresh process, like a real rebuild: moto makes its default resources on first use, so a moto test
    # run earlier in this process would shift the seeded IDs.
    code = ("import runpy, sys; from pathlib import Path; "
            "runpy.run_path(sys.argv[1], run_name='make_sample')['build_sample'](Path(sys.argv[2]))")
    subprocess.run([sys.executable, "-c", code, str(COLLECTOR / "scripts" / "make_sample.py"), str(tmp_path)],
                   check=True, cwd=COLLECTOR, capture_output=True)
    built = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*.json"))
    assert len(built) >= 3, built
    for rel in built:
        assert (tmp_path / rel).read_text() == (SAMPLES / rel).read_text(), f"{rel} differs: run make_sample.py"

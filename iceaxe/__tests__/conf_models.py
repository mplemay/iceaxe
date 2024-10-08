from contextlib import contextmanager
from pathlib import Path

from pyinstrument import Profiler

from iceaxe.base import Field, TableBase


class UserDemo(TableBase):
    id: int = Field(primary_key=True, default=None)
    name: str
    email: str


@contextmanager
def run_profile(request):
    TESTS_ROOT = Path.cwd()
    PROFILE_ROOT = TESTS_ROOT / ".profiles"

    # Turn profiling on
    profiler = Profiler()
    profiler.start()

    yield  # Run test

    profiler.stop()
    PROFILE_ROOT.mkdir(exist_ok=True)
    results_file = PROFILE_ROOT / f"{request.node.name}.html"
    profiler.write_html(results_file)

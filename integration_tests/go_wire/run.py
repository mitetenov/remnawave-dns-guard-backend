"""Run both Go services over real HTTP, with only provider/probe I/O replaced."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    backend = Path(__file__).resolve().parents[2]
    parser.add_argument("--agent", type=Path, default=backend.parent / "agent")
    args = parser.parse_args()
    agent = args.agent.resolve()
    if not (agent / "go.mod").is_file():
        parser.error("--agent must point to the Go agent source checkout")
    with tempfile.TemporaryDirectory(prefix="dns-guard-go-wire-") as directory:
        root = Path(directory)
        (root / "go.mod").write_text(
            "module dns-guard-wire-tests\n\ngo 1.27.0\n\nrequire (\n"
            " github.com/mitetenov/remnawave-dns-guard-backend v0.0.0\n"
            " github.com/mitetenov/remnawave-dns-guard-agent v0.0.0\n)\n\n"
            "replace github.com/mitetenov/remnawave-dns-guard-backend => "
            + json.dumps(str(backend))
            + "\nreplace github.com/mitetenov/remnawave-dns-guard-agent => "
            + json.dumps(str(agent)) + "\n"
        )
        shutil.copyfile(Path(__file__).with_name("wire_test.go.txt"), root / "wire_test.go")
        subprocess.run(
            [os.environ.get("GO_BINARY", "go"), "test", "-mod=mod", "-race", "-tags", "wire", "-count=1", "-v", "."],
            cwd=root, check=True, timeout=300,
        )


if __name__ == "__main__":
    main()

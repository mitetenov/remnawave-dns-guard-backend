"""Check the real backend container and SQLite session persistence without providers."""
import http.cookiejar
import json
import pathlib
import sqlite3
import subprocess
import sys
import time
import tempfile
import urllib.error
import urllib.request
import uuid


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def main(image):
    assert docker("image", "inspect", image, "--format", "{{.Architecture}}") == "amd64"
    assert docker("image", "inspect", image, "--format", "{{.Config.User}}") in ("10001", "10001:10001")
    name = "guard-backend-smoke-" + uuid.uuid4().hex[:12]
    origin = "http://guard-smoke.test"
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    try:
        docker("run", "--platform", "linux/amd64", "-d", "--name", name, "-p", "127.0.0.1::8000", "-v", "/data",
               "-e", "ADMIN_USERNAME=smoke", "-e", "ADMIN_PASSWORD=smoke-only-password",
               "-e", "APP_SECRET=" + "S" * 32, "-e", "AGENT_TOKEN=" + "T" * 32,
               "-e", "COOKIE_SECURE=false", "-e", "PUBLIC_ORIGIN=" + origin, image)
        port = docker("port", name, "8000/tcp").rsplit(":", 1)[1]
        base = "http://127.0.0.1:" + port

        def request(path, data=None, headers=None):
            body = None if data is None else json.dumps(data).encode()
            req = urllib.request.Request(base + path, data=body,
                headers={"Origin": origin, "Content-Type": "application/json", **(headers or {})})
            with opener.open(req, timeout=3) as response:
                return json.load(response)

        def wait():
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                try:
                    assert request("/api/health") == {"ok": True}
                    return
                except (OSError, AssertionError):
                    time.sleep(0.5)
            raise RuntimeError("Backend did not become healthy")

        wait()
        try:
            request("/api/auth/me")
            raise AssertionError("Anonymous request was accepted")
        except urllib.error.HTTPError as error:
            assert error.code == 401
        assert request("/api/auth/login", {"username": "smoke", "password": "smoke-only-password"}) == {"username": "smoke"}
        assert request("/api/auth/me") == {"username": "smoke"}
        assert request("/api/pools") == []
        poll = request("/api/agent/poll", {"agent_id": "ci-smoke", "version": "ci", "control_ok": True, "control_error": None},
                       {"Authorization": "Bearer " + "T" * 32})
        assert poll["jobs"] == []
        docker("exec", name, "/dns-guard", "--healthcheck")
        docker("exec", name, "/dns-guard", "--backup", "/tmp/guard-smoke-backup.db")
        with tempfile.TemporaryDirectory(prefix="guard-backend-backup-") as directory:
            snapshot = pathlib.Path(directory) / "backup.db"
            docker("cp", name + ":/tmp/guard-smoke-backup.db", str(snapshot))
            with sqlite3.connect(snapshot) as db:
                assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                assert db.execute("SELECT count(*) FROM sessions").fetchone()[0] == 1
            docker("cp", str(snapshot), name + ":/data/restore-source.db")
        docker("restart", name)
        # An ephemeral host port can be reassigned when Docker restarts the container.
        port = docker("port", name, "8000/tcp").rsplit(":", 1)[1]
        base = "http://127.0.0.1:" + port
        wait()
        assert request("/api/auth/me") == {"username": "smoke"}
        docker("stop", name)
        docker("run", "--rm", "--platform", "linux/amd64", "--network", "none",
               "--volumes-from", name, "--user", "0", "-e", "DATABASE_PATH=/data/guard.db",
               image, "--restore", "/data/restore-source.db")
        docker("start", name)
        port = docker("port", name, "8000/tcp").rsplit(":", 1)[1]
        base = "http://127.0.0.1:" + port
        wait()
        assert request("/api/auth/me") == {"username": "smoke"}
        docker("stop", name)
        with tempfile.TemporaryDirectory(prefix="guard-backend-db-") as directory:
            docker("cp", name + ":/data/.", directory)
            with sqlite3.connect(pathlib.Path(directory) / "guard.db") as db:
                assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        print("Backend image: health, auth, agent poll, UID, live SQLite backup, offline restore, restart persistence and integrity passed")
    except Exception:
        subprocess.run(["docker", "logs", name], check=False)
        raise
    finally:
        subprocess.run(["docker", "rm", "-f", "-v", name], stdout=subprocess.DEVNULL, check=False)


if __name__ == "__main__":
    main(sys.argv[1])

"""Check the real backend container and SQLite session persistence without providers."""
import http.cookiejar
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def main(image):
    name = "guard-backend-smoke-" + uuid.uuid4().hex[:12]
    origin = "http://guard-smoke.test"
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    try:
        docker("run", "-d", "--name", name, "-p", "127.0.0.1::8000",
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
        assert docker("exec", name, "python", "-c", "import os; print(os.getuid())") == "10001"
        docker("restart", name)
        # An ephemeral host port can be reassigned when Docker restarts the container.
        port = docker("port", name, "8000/tcp").rsplit(":", 1)[1]
        base = "http://127.0.0.1:" + port
        wait()
        assert request("/api/auth/me") == {"username": "smoke"}
        integrity = docker("exec", name, "python", "-c",
            "import sqlite3; print(sqlite3.connect('/data/guard.db').execute('PRAGMA integrity_check').fetchone()[0])")
        assert integrity == "ok"
        print("Backend image: health, auth, agent poll, UID, restart persistence and SQLite integrity passed")
    except Exception:
        subprocess.run(["docker", "logs", name], check=False)
        raise
    finally:
        subprocess.run(["docker", "rm", "-f", "-v", name], stdout=subprocess.DEVNULL, check=False)


if __name__ == "__main__":
    main(sys.argv[1])

"""PostgreSQL connection runner — works with Docker containers, K8s pods, or direct TCP."""
import json
import subprocess  # nosec B404 (required for docker/kubectl/psql CLI execution)
import shlex
from typing import Optional


class PgRunner:
    """
    Executes queries against a PostgreSQL instance.

    Supports three modes:
      - docker:   docker exec <container> psql ...
      - kubectl:  kubectl exec <pod> -n <ns> -- psql ...
      - direct:   psql via TCP (host:port, for Cloud SQL w/ proxy, etc.)
    """

    def __init__(
        self,
        mode: str = "docker",
        container: Optional[str] = None,
        pod: Optional[str] = None,
        namespace: str = "default",
        host: str = "localhost",
        port: int = 5432,
        user: str = "postgres",
        password: Optional[str] = None,
        database: str = "postgres",
        verbose: bool = False,
    ):
        self.mode = mode
        self.container = container
        self.pod = pod
        self.namespace = namespace
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.verbose = verbose

    def _build_psql_cmd(self, sql: str) -> list[str]:
        psql_args = [
            "psql",
            "-U", self.user,
            "-d", self.database,
            "-t",          # tuples only
            "-A",          # unaligned
            "-F", "\x1f",  # field separator = unit separator
            "-c", sql,
        ]

        if self.mode == "docker":
            cmd = ["docker", "exec", "-i"]
            if self.password:
                cmd += ["-e", f"PGPASSWORD={self.password}"]
            return cmd + [self.container] + psql_args

        elif self.mode == "kubectl":
            cmd = ["kubectl", "exec", self.pod, "-n", self.namespace]
            if self.password:
                cmd += ["--env", f"PGPASSWORD={self.password}"]
            return cmd + ["--"] + psql_args

        elif self.mode == "direct":
            psql_args += ["-h", self.host, "-p", str(self.port)]
            return psql_args

        else:
            raise ValueError(f"Unknown mode: {self.mode}")

    def query(self, sql: str) -> list[dict]:
        """Run a SQL query and return list of dicts."""
        cmd = self._build_psql_cmd(sql)
        env = None

        if self.password and self.mode == "direct":
            import os
            env = os.environ.copy()
            env["PGPASSWORD"] = self.password

        if self.verbose:
            print(f"[runner] CMD: {' '.join(shlex.quote(c) for c in cmd)}")
            print(f"[runner] SQL: {sql}")

        try:
            result = subprocess.run(  # nosec B603 (args are list-based, no shell=True)
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return [{"_error": "query timeout"}]
        except FileNotFoundError as e:
            return [{"_error": f"command not found: {e}"}]

        if result.returncode != 0:
            if self.verbose:
                print(f"[runner] STDERR: {result.stderr.strip()}")
            return [{"_error": result.stderr.strip()}]

        return self._parse_output(result.stdout, sql)

    def _parse_output(self, output: str, sql: str) -> list[dict]:
        """Parse psql -t -A -F '\x1f' output into list of dicts."""
        lines = [l for l in output.strip().splitlines() if l.strip()]
        if not lines:
            return []

        # For SHOW commands, output is just the value
        if sql.strip().upper().startswith("SHOW"):
            return [{sql.strip().split()[1].rstrip(";"): lines[0].strip()}]

        # Try to extract column names from a header query
        # Since we use -t (tuples only), no headers — treat as value-only
        rows = []
        for line in lines:
            parts = line.split("\x1f")
            rows.append({"_cols": parts})
        return rows

    def query_with_cols(self, sql: str, columns: list[str]) -> list[dict]:
        """Run a query and map output to named columns."""
        raw = self.query(sql)
        results = []
        for row in raw:
            if "_error" in row:
                results.append(row)
                continue
            parts = row.get("_cols", [])
            mapped = {}
            for i, col in enumerate(columns):
                mapped[col] = parts[i] if i < len(parts) else None
            results.append(mapped)
        return results

    def file_contents(self, path: str) -> Optional[str]:
        """Read a file from inside the container."""
        if self.mode == "docker":
            cmd = ["docker", "exec", self.container, "cat", path]
        elif self.mode == "kubectl":
            cmd = ["kubectl", "exec", self.pod, "-n", self.namespace, "--", "cat", path]
        else:
            return None

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)  # nosec B603 (list args, fixed executable)
            if result.returncode == 0:
                return result.stdout
            return None
        except Exception:
            return None

    def exec_cmd(self, command: list[str]) -> Optional[str]:
        """Run an arbitrary command inside the container."""
        if self.mode == "docker":
            cmd = ["docker", "exec", self.container] + command
        elif self.mode == "kubectl":
            cmd = ["kubectl", "exec", self.pod, "-n", self.namespace, "--"] + command
        else:
            return None

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)  # nosec B603 (list args, fixed executable)
            return result.stdout if result.returncode == 0 else None
        except Exception:
            return None

    def test_connection(self) -> bool:
        """Verify we can reach the database."""
        rows = self.query("SELECT 1 AS ok;")
        return bool(rows) and "_error" not in rows[0]

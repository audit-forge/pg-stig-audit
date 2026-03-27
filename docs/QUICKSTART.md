# QuickStart

This guide is the fastest, easiest way to run `pg-stig-audit`.

If you do not want to read a bunch of docs, start here.

---

## What this tool does

`pg-stig-audit` checks whether a PostgreSQL deployment looks secure or risky.

It gives you a report with results like:
- `PASS` = looks good
- `FAIL` = needs fixing
- `WARN` = pay attention

---

## What you need first

You need:
- `python3`
- the `pg-stig-audit` repo
- a PostgreSQL target to test

Your PostgreSQL target can be one of these:
- a Docker container
- a Kubernetes pod
- a PostgreSQL server reachable by host + port

---

## Copy/paste setup

```bash
git clone https://github.com/audit-forge/pg-stig-audit.git
cd pg-stig-audit
python3 --version
python3 audit.py --version
```

If those commands run, you are ready.

---

## Fastest possible commands

### Docker

```bash
python3 audit.py --mode docker --container my-postgres
```

### Kubernetes

```bash
python3 audit.py --mode kubectl --pod postgres-0 --namespace default
```

### Direct host/port

```bash
python3 audit.py --mode direct --host 127.0.0.1 --port 5432 --user postgres --database postgres
```

---

## Save the results to files

If you want files you can keep or send to someone:

### Docker example

```bash
python3 audit.py --mode docker --container my-postgres \
  --json results.json \
  --sarif results.sarif.json \
  --csv results.csv \
  --bundle evidence.zip
```

### Direct-mode example

```bash
python3 audit.py --mode direct --host 127.0.0.1 --port 5432 --user postgres --database postgres \
  --json results.json \
  --sarif results.sarif.json \
  --csv results.csv \
  --bundle evidence.zip
```

Files created:
- `results.json` = full results
- `results.sarif.json` = security-platform format
- `results.csv` = spreadsheet format
- `evidence.zip` = evidence package

---

## If PostgreSQL needs a password

Set the password first:

```bash
export PGPASSWORD='your-password-here'
```

Then run the audit command.

Example:

```bash
export PGPASSWORD='your-password-here'
python3 audit.py --mode direct --host 127.0.0.1 --port 5432 --user postgres --database postgres
```

---

## If you need the Docker container name

Run:

```bash
docker ps --format '{{.Names}}'
```

Then use the right name in the command.

---

## If you need the Kubernetes pod name

Run:

```bash
kubectl get pods -n default
```

Then use the right pod name in the command.

---

## Easiest self-test

If you want to prove the tool works before using it on a real PostgreSQL server, run the built-in fixtures:

```bash
make test-fixtures
```

This will:
1. start test PostgreSQL containers
2. run the audit against them
3. write output to `test/output/`
4. stop the test containers

---

## Super simple troubleshooting

### Docker command fails

Check whether the container is running:

```bash
docker ps
```

### Kubernetes command fails

Check whether the pod exists:

```bash
kubectl get pods -n default
```

### Direct mode fails

Check whether PostgreSQL responds:

```bash
psql -h 127.0.0.1 -p 5432 -U postgres -d postgres -c 'select version();'
```

### Password-protected PostgreSQL fails

Make sure you set:

```bash
export PGPASSWORD='your-password'
```

---

## Where to go next

- `docs/BEGINNER_GUIDE.md` — plain-English step-by-step instructions
- `docs/RUN_BENCHMARK.md` — fuller operator guide
- `test/README.md` — fixture testing flow
- `docs/V1_RELEASE_BOUNDARY.md` — current v1.0 scope and positioning

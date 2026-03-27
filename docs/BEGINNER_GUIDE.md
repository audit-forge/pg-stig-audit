# Beginner Guide

This guide is written for someone who wants very direct instructions.

You do **not** need to be a PostgreSQL expert.

---

## What you are doing

You are running a tool that checks whether PostgreSQL is set up safely.

Think of it like this:
- PostgreSQL = the thing you want to inspect
- `pg-stig-audit` = the inspector
- output report = the scorecard

---

## Step 1: download the tool

Open Terminal and type:

```bash
git clone https://github.com/audit-forge/pg-stig-audit.git
cd pg-stig-audit
```

---

## Step 2: make sure Python works

Type:

```bash
python3 --version
python3 audit.py --version
```

---

## Step 3: choose what kind of PostgreSQL you have

### Choice A: PostgreSQL is running in Docker

Find the container name:

```bash
docker ps --format '{{.Names}}'
```

Then run:

```bash
python3 audit.py --mode docker --container my-postgres
```

---

### Choice B: PostgreSQL is running in Kubernetes

Find the pod name:

```bash
kubectl get pods -n default
```

Then run:

```bash
python3 audit.py --mode kubectl --pod postgres-0 --namespace default
```

---

### Choice C: PostgreSQL is reachable by IP address and port

Run:

```bash
python3 audit.py --mode direct --host 127.0.0.1 --port 5432 --user postgres --database postgres
```

If PostgreSQL is somewhere else, replace the IP address.

---

## Step 4: if PostgreSQL needs a password

Set it first:

```bash
export PGPASSWORD='your-password'
```

Then run the normal command.

---

## Step 5: understand the results

You will see things like:
- `PASS`
- `FAIL`
- `WARN`

What they mean:
- `PASS` = good
- `FAIL` = bad, needs fixing
- `WARN` = maybe okay, maybe risky, look at it

---

## Step 6: save the results to files

If you want files you can keep, share, or upload:

```bash
python3 audit.py --mode docker --container my-postgres \
  --json results.json \
  --sarif results.sarif.json \
  --csv results.csv \
  --bundle evidence.zip
```

---

## Step 7: easiest way to test the tool itself

If you just want to make sure the tool works, use the built-in test setup:

```bash
make test-fixtures
```

This starts test PostgreSQL containers, audits them, and stops them.

---

## If something goes wrong

### Docker version fails

Check if PostgreSQL is running:

```bash
docker ps
```

### Kubernetes version fails

Check if the pod exists:

```bash
kubectl get pods -n default
```

### Direct version fails

See if PostgreSQL answers at all:

```bash
psql -h 127.0.0.1 -p 5432 -U postgres -d postgres -c 'select version();'
```

### Password problems

Set the password first:

```bash
export PGPASSWORD='your-password'
```

---

## Short version

Clone the repo, point the tool at your PostgreSQL server, run one command, and read the `PASS` / `FAIL` / `WARN` report.

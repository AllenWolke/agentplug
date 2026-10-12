# First installation and login

[Developer path](README.md) · [简体中文](../zh/quickstart.md)

These steps are for a **new environment**. Existing installations should inspect `status` and `smoke`, preserve accounts and use the migration workflow for upgrades.

## 1. Check tools

Run from the repository root:

```text
python --version
docker version
docker compose version
```

Requirements: Python 3.12+, a running Docker engine and Compose v2. Initial builds download images and Go, Node and Python dependencies. The base stack does not require Go, Node or Java on the host; development in those languages does.

## 2. Prepare private configuration

```text
python -m pip install "cryptography>=50,<51"
python scripts/prepare_local_development.py
```

Enter and confirm your first administrator password. The script creates `.env` with independent random database/service credentials and matching execution keys, plus `.local-secrets/first-admin.json` with the one-time administrator request. It prints no secrets and starts no services.

Default administrator: `platform.admin`. This is a platform administration/recovery identity, without automatic business execution rights. The initial company is `tenant-demo`, administration department `dept-platform`, internal Application `app-platform-admin`.

If default ports conflict, choose alternatives **instead of the default preparation command**, for example:

```text
python scripts/prepare_local_development.py --frontend-port 33000 --postgres-port 35432
```

Existing files are never overwritten. Restrict Windows ACLs to the operator; POSIX files are created with mode 0600. Both files are ignored by Git. Do not include them in screenshots, Issues or agent images.

## 3. Validate and initialize

```text
python scripts/compose.py config --env-file .env
python scripts/init_platform.py --env-file .env
```

`config` validates without printing interpolated secrets. `init` builds the migration image, starts PostgreSQL/Kafka, migrates the schema, provisions the development runtime role and creates message topics. Migration credentials do not enter the long-lived platform process.

If initialization fails, stop here and use [troubleshooting](troubleshooting.md). Do not delete data volumes or migration history to bypass an error.

## 4. Bootstrap the first administrator

```text
python scripts/bootstrap_first_admin.py --env-file .env --config .local-secrets/first-admin.json
```

Expected output: `FIRST ADMINISTRATOR BOOTSTRAP PASS`. The command requires the current schema and an empty identity store. It does not overwrite accounts. Production uses real OIDC bindings; see the [administrator maintenance reference, Chinese](../../../deploy/README-first-administrator.md).

After successful initialization, the operator may remove the one-time JSON while securely retaining access/recovery information. Removing the file does not remove the database account. Keep `.env` for service operation.

## 5. Start and verify

```text
python scripts/compose.py up --env-file .env
python scripts/compose.py status --env-file .env
python scripts/compose.py smoke --env-file .env
```

The default five services are platform, frontend, PostgreSQL, Kafka and Metric Runner. Open `http://127.0.0.1:3000` or your configured port. Sign in with `platform.admin` and the password entered earlier. Check language switching, help and your management scope.

## 6. Continue and stop

This proves base-platform availability. Business examples, providers, knowledge contents and permissions are not created automatically. Continue with [first-agent development](first-agent.md) and [delivery](delivery.md).

```text
python scripts/compose.py down --env-file .env
```

`down` preserves data volumes. `reset --force` deletes data and is reserved for explicitly disposable isolated environments.

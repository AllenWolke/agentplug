#!/bin/sh
set -eu

if [ -z "${MINIO_ROOT_PASSWORD:-}" ]; then
  echo "MinIO in the full profile requires EVALUATION_ARTIFACT_S3_SECRET_KEY in the private Compose env file." >&2
  exit 2
fi

# The pinned MinIO image declares this official entrypoint; delegate all original
# arguments unchanged so the image retains its standard startup behavior.
exec /usr/bin/docker-entrypoint.sh "$@"

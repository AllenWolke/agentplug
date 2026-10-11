# Build from repository root: install the repository SDK, not a remote copy.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /workspace
COPY sdk/python/ /workspace/sdk/python/
COPY examples/python-documents/pyproject.toml /workspace/example-dependencies.toml
RUN python -c "import subprocess,tomllib; requirements=tomllib.load(open('/workspace/example-dependencies.toml','rb'))['project']['dependencies']; subprocess.check_call(['python','-m','pip','install','--disable-pip-version-check','/workspace/sdk/python','setuptools','wheel',*requirements])"
COPY examples/python-documents/ /workspace/examples/python-documents/
RUN python -m pip install --disable-pip-version-check --no-deps --no-build-isolation /workspace/examples/python-documents
USER 65532:65532
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["python", "-m", "document_assistant.server"]

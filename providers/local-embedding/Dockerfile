FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 OMP_NUM_THREADS=4 MKL_NUM_THREADS=4
WORKDIR /opt/provider
COPY providers/local-embedding/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir torch==2.12.0 --index-url https://download.pytorch.org/whl/cpu && pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home provider
COPY providers/local-embedding/ ./
USER 10001:10001
EXPOSE 8091
ENTRYPOINT ["python", "server.py"]

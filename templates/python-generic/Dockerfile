FROM python:3.12-slim
WORKDIR /app
# The index is overridable so restricted or mirrored networks can build the same
# image; the default keeps upstream PyPI. / 索引可覆盖，便于受限或镜像网络构建
# 同一镜像；默认仍为上游 PyPI。
ARG PIP_INDEX_URL=https://pypi.org/simple
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --retries 10 --timeout 120 --index-url "${PIP_INDEX_URL}" --requirement /app/requirements.txt
COPY . /app
RUN addgroup --system agent && adduser --system --ingroup agent agent
USER agent
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=12 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/ready')"
CMD ["python", "platform_entry/server.py"]

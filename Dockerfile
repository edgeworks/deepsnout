FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEEPSNOUT_DATA_DIR=/var/lib/deepsnout
RUN apt-get update && apt-get install -y --no-install-recommends libpsl5 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 deepsnout \
    && useradd --uid 10001 --gid 10001 --create-home deepsnout \
    && mkdir -p /var/lib/deepsnout && chown 10001:10001 /var/lib/deepsnout
WORKDIR /app
COPY pyproject.toml LICENSE README.md ./
COPY deepsnout ./deepsnout
RUN pip install --no-cache-dir .
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["deepsnout"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]

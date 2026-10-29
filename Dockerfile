FROM python:3.12-slim

LABEL org.opencontainers.image.title="explainfail" \
      org.opencontainers.image.description="Plain-English explanations for failed jobs and scripts" \
      org.opencontainers.image.source="https://github.com/malviyashreekant/explainfail" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install . && useradd --create-home --uid 10001 explainfail

USER explainfail
WORKDIR /work
ENTRYPOINT ["explainfail"]
CMD ["--help"]

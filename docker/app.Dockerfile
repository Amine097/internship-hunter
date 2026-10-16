FROM python:3.15-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY hunter ./hunter
RUN pip install --no-cache-dir .
COPY config ./config
RUN useradd --no-create-home --uid 10001 hunter
USER hunter

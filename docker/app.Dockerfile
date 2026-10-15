FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY hunter ./hunter
RUN pip install --no-cache-dir .
COPY config ./config
RUN useradd --create-home --uid 10001 hunter
USER hunter

FROM node:25-bookworm-slim AS node
FROM python:3.12-slim-bookworm
ARG CLAUDE_CODE_VERSION=2.1.301
ARG CODEX_VERSION=0.162.1
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" "@openai/codex@${CODEX_VERSION}" \
 && npm cache clean --force
WORKDIR /app
COPY pyproject.toml README.md ./
COPY hunter ./hunter
RUN pip install --no-cache-dir .
COPY config ./config
RUN useradd --create-home --uid 10001 hunter \
 && mkdir -p /home/hunter/.claude /home/hunter/.codex && chown -R hunter:hunter /home/hunter
ENV HOME=/home/hunter
USER hunter

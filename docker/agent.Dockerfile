FROM node:22-bookworm-slim AS node
FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/bin/npm /usr/local/bin/npm
COPY --from=node /usr/local/bin/npx /usr/local/bin/npx
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm-cli.js || true
RUN npm install -g @anthropic-ai/claude-code @openai/codex && npm cache clean --force
WORKDIR /app
COPY pyproject.toml README.md ./
COPY hunter ./hunter
RUN pip install --no-cache-dir .
COPY config ./config
RUN useradd --create-home --uid 10001 hunter && mkdir -p /home/hunter/.claude /home/hunter/.codex && chown -R hunter:hunter /home/hunter
ENV HOME=/home/hunter
USER hunter

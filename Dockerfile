# Python 3.14: the full test suite (including the browser-driven end-to-end
# tests) passes on it, and it is the newest release with wheels for every
# runtime dependency.
ARG PYTHONVER=3.14
ARG DISTROBASE=bookworm
FROM ghcr.io/astral-sh/uv:python${PYTHONVER}-${DISTROBASE}-slim AS builder
# only-system forces the venv to link against the interpreter baked into this
# image. Left to itself, uv honours .python-version and downloads a *managed*
# interpreter under /root/.local/share/uv/, which the final stage does not copy
# — leaving .venv/bin/python3 dangling, so `python3` silently falls back to the
# system interpreter and the app starts without its dependencies.
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_PREFERENCE=only-system
WORKDIR /app
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev
ADD . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# Then, use a final image without uv
FROM python:${PYTHONVER}-slim-${DISTROBASE}
# It is important to use the image that matches the builder, as the path to the
# Python executable must be the same, e.g., using `python:3.11-slim-bookworm`
# will fail.

# Run unprivileged. /app must remain writable by that user: the default
# SQLALCHEMY_DATABASE_URI puts app.db alongside config.py, and /health prunes
# expired rows on every call.
RUN useradd --create-home --uid 1000 app

# Copy the application from the builder
COPY --from=builder --chown=app:app /app /app

# Place executables in the environment at the front of the path.
# PYTHONUNBUFFERED keeps logs streaming rather than sitting in a pipe buffer.
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

USER app
WORKDIR /app
EXPOSE 8000

# Fail the build, not the deployment, if `python3` is not the venv interpreter or
# the app cannot be constructed. A dangling .venv symlink makes `python3` fall
# back to the system interpreter, which imports nothing and only fails at boot.
# create_app() creates the database, so point it at a throwaway path: the real
# one must be created on first boot, never baked into the image.
RUN python3 -c "import sys; assert sys.prefix == '/app/.venv', sys.prefix" \
    && DATABASE_URI=sqlite:////tmp/buildcheck.db python3 -c "from app import create_app; create_app()" \
    && rm -f /tmp/buildcheck.db \
    && test ! -e /app/app.db

CMD ["python3", "/app/app.py"]

# Probe with the interpreter that is already here rather than installing curl:
# it keeps the image free of an apt layer and of a package the app never uses.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python3", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health', timeout=2).status == 200 else 1)"]

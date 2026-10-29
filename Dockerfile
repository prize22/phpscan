# syntax=docker/dockerfile:1
# PHPSCAN runtime image.
#
# Two stages so the final image carries only the runtime dependency set
# (tree-sitter, tree-sitter-php, PyYAML) and never the development extras
# (pytest, pytest-cov, ruff) declared under [project.optional-dependencies].dev.
#
# The image deliberately contains NO PHP interpreter: phpscan parses PHP with
# tree-sitter and must never execute target code.

########## builder ##########
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

# Only what the package build needs: setuptools reads pyproject.toml, the
# readme, and the phpscan package. Tests, the eval corpus, docs and CI config
# are deliberately not copied into the image.
COPY pyproject.toml README.md ./
COPY phpscan/ ./phpscan/

# pip wheel resolves the runtime dependencies only (no extras) and leaves both
# them and the phpscan wheel in /wheels for an offline final-stage install.
RUN python -m pip install --upgrade "pip>=24" \
    && python -m pip wheel --wheel-dir /wheels .

########## runtime ##########
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Non-root by default. Fixed high UID/GID (10001) so mounted-volume ownership
# is predictable; override per run with --user "$(id -u):$(id -g)".
RUN groupadd --gid 10001 phpscan \
    && useradd --uid 10001 --gid 10001 --create-home \
        --home-dir /home/phpscan --shell /usr/sbin/nologin phpscan

# Predictable working directory: mount the code under review here.
WORKDIR /work
RUN chown phpscan:phpscan /work

COPY --from=builder /wheels /wheels
RUN python -m pip install --no-index --find-links=/wheels phpscan \
    && rm -rf /wheels \
    && phpscan --version

USER phpscan
ENV HOME=/home/phpscan

ENTRYPOINT ["phpscan"]
CMD ["--help"]

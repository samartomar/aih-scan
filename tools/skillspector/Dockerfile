# Hermetic SkillSpector OCI build recipe, moved from Core
# (D:/dev/ai-harness/tools/skillspector.Dockerfile) to Scan under the package
# separation. Build context is a checkout of NVIDIA/SkillSpector at the pinned
# commit below (v2.12.0). Build inputs (base image digest, uv version,
# UV_EXCLUDE_NEWER cutoff) follow Core's src/internals/external-pin-ledger.json;
# the cutoff moved 2026-08-15 -> 2026-09-24 because it must sit at or after the
# source commit date (2026-09-23T22:27:53Z). Moving any pinned input is a pin
# rotation: it changes the digest and requires a re-vet.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134

FROM ${PYTHON_IMAGE} AS builder

ARG SOURCE_DATE_EPOCH=1790202473
# UV_EXCLUDE_NEWER is a pinned build input, not a convenience. `uv.lock` pins the
# runtime dependencies but not the PEP 517 backends that build the packages
# compiled from source. Without a date cutoff those backends resolve to whatever
# PyPI serves at build time, so a setuptools or hatchling release rewrites their
# .dist-info metadata and changes the image digest. This cutoff restores the
# resolution that produced the controlled digest, which is what makes that
# digest independently rebuildable.
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    UV_NO_PROGRESS=1 \
    UV_EXCLUDE_NEWER=2026-09-24T00:00:00Z
WORKDIR /app
RUN pip install --no-cache-dir uv==0.12.8
COPY pyproject.toml uv.lock README.md ./
COPY src/ src/
RUN uv sync --frozen --no-dev --no-editable \
    && find .venv/lib/python3.12/site-packages \
      -path '*/skillspector-*.dist-info/uv_cache.json' -delete \
    && find .venv/lib/python3.12/site-packages \
      -path '*/skillspector-*.dist-info/RECORD' -delete \
    && tar --format=gnu --sort=name --hard-dereference \
      --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner \
      -cf /venv.tar .venv \
    && touch -d "@${SOURCE_DATE_EPOCH}" /venv.tar

FROM ${PYTHON_IMAGE}

ARG SOURCE_DATE_EPOCH=1790202473
LABEL org.opencontainers.image.revision="c7958a3268d9498644b22edb75d0f051bbc8cbfc"
ENV PATH="/app/.venv/bin:$PATH" \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
RUN --mount=from=builder,source=/venv.tar,target=/tmp/venv.tar \
    mkdir -p /app \
    && tar -xf /tmp/venv.tar -C /app \
    && touch -d "@${SOURCE_DATE_EPOCH}" /app /tmp
WORKDIR /scan
ENTRYPOINT ["skillspector"]

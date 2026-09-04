FROM python:3.12-slim-bookworm@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134 AS builder
ARG SOURCE_DATE_EPOCH=1785167267
ENV SOURCE_DATE_EPOCH=1785167267 UV_EXCLUDE_NEWER=2026-09-02T00:00:00Z
ENV CISCO_WHEEL_SHA256=30b5c8a5108307981e0299e6cde0da869be64deb5da0ca66cf9f0022c3c48fc2
RUN python -m pip install "https://files.pythonhosted.org/packages/93/22/dacc9a0bc8604187a1ba954a3aef8329e4104eb0af772d2c3c634893bd9b/uv-0.12.5-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl#sha256=3e195ccf1ed60c8bb24a6447ce306441a4181d54b602407e09bc56e963911c15"
WORKDIR /runtime
COPY pyproject.toml uv.lock ./
RUN printf '%s  %s\n%s  %s\n' '68c2649f7a724a465546d0a500d668ec5ed41e526391f8dee4d8513efdca806f' pyproject.toml 'aaba1f3260494b09dfc62fd6c309558b901b8ad9411587d534a4f09721d3b4a1' uv.lock | sha256sum -c - && uv sync --frozen
RUN tar --sort=name --mtime=@1785167267 -cf /runtime-venv.tar .venv

FROM python:3.12-slim-bookworm@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134
WORKDIR /runtime
COPY --from=builder /runtime-venv.tar /runtime-venv.tar
RUN tar -xf /runtime-venv.tar && rm /runtime-venv.tar
USER 65532:65532
ENTRYPOINT ["/runtime/.venv/bin/skill-scanner"]

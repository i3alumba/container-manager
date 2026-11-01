# Official manifest digest verified by the operator; non-root controller only.
FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
WORKDIR /app
RUN pip install --no-cache-dir uv==0.13.6
COPY pyproject.toml uv.lock ./
COPY container_manager ./container_manager
RUN chmod a+r pyproject.toml uv.lock \
    && chmod -R a+rX container_manager \
    && uv sync --locked --no-dev --no-editable \
    && useradd --uid 10001 --create-home manager \
    && mkdir /state && chown manager:manager /state
USER 10001:10001
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
# Also gates restrictive CI snapshot modes as the actual runtime UID.
RUN python -c "import container_manager.api, container_manager.rpc" \
    && container-manager --help >/dev/null
ENTRYPOINT ["container-manager", "--config"]
CMD ["/etc/container-manager/config.json"]

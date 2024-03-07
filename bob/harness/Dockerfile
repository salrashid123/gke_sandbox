FROM debian:11-slim AS build
RUN apt-get update && \
    apt-get install --no-install-suggests --no-install-recommends --yes python3-venv gcc libpython3-dev && \
    python3 -m venv /venv && \
    /venv/bin/pip install --upgrade pip setuptools wheel

FROM build AS build-venv
COPY requirements.txt /requirements.txt
RUN /venv/bin/pip install --disable-pip-version-check -r /requirements.txt


FROM gcr.io/distroless/python3-debian12@sha256:06fd54a776cb38ee6f71f01c799f7388b8ed96333ad81dd2a8fdd648a895ff79
COPY --from=build-venv /venv /venv
COPY . /app
WORKDIR /app
ENTRYPOINT ["/venv/bin/python3", "main.py"]
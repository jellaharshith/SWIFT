# Stage 1: builder
FROM python:3.10-slim AS builder
WORKDIR /build
COPY swift/ .
RUN pip install --no-cache-dir --prefix=/install -r requirement.txt && \
    pip install --no-cache-dir --prefix=/install .

# Stage 2: runtime
FROM python:3.10-slim
WORKDIR /app
COPY --from=builder /install /usr/local
COPY swift/ .
RUN rm -rf .venv __pycache__ test/.venv
ENV SWIFT_ENV=apprunner
ENTRYPOINT ["swiftsec"]
CMD ["--help"]

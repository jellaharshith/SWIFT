# Stage 1: builder
FROM python:3.10-slim AS builder
WORKDIR /build
COPY requirement.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirement.txt

# Stage 2: runtime
FROM python:3.10-slim
WORKDIR /app
COPY --from=builder /install /usr/local
COPY . .
# Remove venv and test artifacts from image
RUN rm -rf .venv __pycache__ test/.venv
ENV PYTHONPATH=/app
EXPOSE 8000
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]

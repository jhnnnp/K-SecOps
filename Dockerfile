# Agentic K-SecOps — production-style image for self-scan (Trivy/Checkov CI target)
FROM python:3.11-slim

WORKDIR /app

RUN groupadd --system app && useradd --system --gid app app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir "mcp>=1.27,<2" fastapi "uvicorn[standard]" pydantic

ENV PYTHONPATH=/app/src
USER app

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "src"]

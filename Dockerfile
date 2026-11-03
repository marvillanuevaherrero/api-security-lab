FROM python:3.12-slim
WORKDIR /lab
COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir .
ENV LAB_MODE=hardened
EXPOSE 8000
USER 65534:65534
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p data models
RUN python train.py
EXPOSE 5050
HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD curl -f http://localhost:5050/health || exit 1
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5050", "--access-logfile", "-", "app:app"]

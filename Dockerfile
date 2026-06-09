FROM python:3.12-slim

# openssh-client is required for the reboot/shutdown (SSH) feature
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

# PORT is configurable (default 8765) — handy when 8765 is already in use.
EXPOSE 8765
CMD ["sh", "-c", "exec gunicorn -b 0.0.0.0:${PORT:-8765} --workers 2 --timeout 60 app:app"]

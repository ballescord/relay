FROM python:3.12-slim

# openssh-client is required for the reboot/shutdown (SSH) feature
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

EXPOSE 8765
CMD ["gunicorn", "-b", "0.0.0.0:8765", "app:app"]

FROM python:3.11-slim

# Prevent python .pyc files
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt /app/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application files
COPY app.py /app/train_from_sources.py
COPY feature_extractor.py /app/feature_extractor.py

# Create dataset mount path (optional)
RUN mkdir -p /datasets /models

# This container runs *once* then exits
CMD ["python", "-u", "train_from_sources.py", "--from-neo4j"]
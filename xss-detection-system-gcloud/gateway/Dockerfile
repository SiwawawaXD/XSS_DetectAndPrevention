FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir \
    flask==3.0.0 \
    requests==2.31.0 \
    elasticsearch==8.11.0 \
    neo4j==5.14.0

# Copy application files
COPY app.py /app/

# Create logs directory
RUN mkdir -p /logs

EXPOSE 8000

CMD ["python", "app.py"]
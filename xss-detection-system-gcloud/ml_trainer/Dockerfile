FROM python:3.10-slim
WORKDIR /app
RUN apt-get update && apt-get install -y gcc
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY train_model.py .
COPY feature_extractor.py .
COPY datasets /datasets
CMD ["python", "train_model.py"]
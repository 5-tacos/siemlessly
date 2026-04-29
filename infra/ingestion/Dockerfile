FROM python:3.12-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir boto3 pyarrow pyyaml

# Copy the ingestion script
COPY extract_to_parquet.py /app/

# The CMD will execute the script
CMD ["python", "extract_to_parquet.py"]

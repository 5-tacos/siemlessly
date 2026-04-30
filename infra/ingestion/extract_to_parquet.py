import os
import json
import tarfile
import boto3
import pyarrow as pa
import pyarrow.parquet as pq
from io import BytesIO
from urllib.parse import urlparse

S3_BUCKET = os.environ.get('S3_BUCKET', 'siem-data-local')

s3_client = boto3.client('s3')


def process_tarball(bucket, key):
    """
    Streams a tarball from S3, parses JSON logs, and writes them to Parquet.
    """
    prefix = os.path.dirname(key)
    
    # We will buffer rows into memory before writing out to Parquet.
    # For a 15GB tarball, we MUST batch writes to avoid OOM.
    BATCH_SIZE = 100_000
    rows = []
    chunk_index = 0
    
    print(f"Starting to stream s3://{bucket}/{key}")
    
    # Get the object stream from S3
    response = s3_client.get_object(Bucket=bucket, Key=key)
    
    # Stream decompression using tarfile
    # Response['Body'] is a StreamingBody, which supports read()
    with tarfile.open(fileobj=response['Body'], mode='r:gz') as tar:
        for member in tar:
            if member.isfile() and member.name.endswith('.json'):
                print(f"Processing inner file: {member.name}")
                f = tar.extractfile(member)
                if not f:
                    continue
                
                # Read line by line to keep memory footprint low
                for line in f:
                    try:
                        record = json.loads(line.decode('utf-8'))
                        # If we have a schema, we could enforce types here
                        # For now, we append the raw dict and let pyarrow infer
                        rows.append(record)
                    except json.JSONDecodeError:
                        continue
                    
                    if len(rows) >= BATCH_SIZE:
                        _write_parquet_chunk(bucket, prefix, rows, chunk_index)
                        rows.clear()
                        chunk_index += 1
                        
        # Flush remaining rows
        if rows:
            _write_parquet_chunk(bucket, prefix, rows, chunk_index)
            
    print(f"Finished processing s3://{bucket}/{key}. Total chunks: {chunk_index + 1}")

def _write_parquet_chunk(bucket, original_prefix, rows, chunk_index):
    if not rows:
        return
        
    print(f"Writing chunk {chunk_index} ({len(rows)} rows) to Parquet...")
    
    # Convert list of dicts to PyArrow Table
    # PyArrow will infer the schema from the first chunk.
    table = pa.Table.from_pylist(rows)
    
    # Write to an in-memory buffer
    buf = BytesIO()
    pq.write_table(table, buf, compression='snappy')
    buf.seek(0)
    
    # Determine new prefix
    # From: raw/source_a/logs.tar.gz
    # To:   processed/source_a/chunk_0.parquet
    base_dir = original_prefix.replace('raw/', '', 1)
    new_key = f"processed/{base_dir}/chunk_{chunk_index:05d}.parquet"
    
    # Upload buffer to S3
    s3_client.put_object(
        Bucket=bucket,
        Key=new_key,
        Body=buf.getvalue()
    )
    print(f"Uploaded chunk {chunk_index} to s3://{bucket}/{new_key}")

if __name__ == "__main__":
    # In Fargate, this script might receive the S3 URL via environment variable
    # or event payload. We'll use an env var for this example.
    target_s3_url = os.environ.get("TARGET_S3_URL")
    if not target_s3_url:
        print("TARGET_S3_URL environment variable is required.")
        exit(1)
        
    parsed = urlparse(target_s3_url)
    bucket_name = parsed.netloc
    object_key = parsed.path.lstrip('/')
    
    process_tarball(bucket_name, object_key)

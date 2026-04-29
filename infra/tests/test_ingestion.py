import os
import json
import pyarrow.parquet as pq
import boto3
from moto import mock_aws
from ingestion.extract_to_parquet import _write_parquet_chunk

@mock_aws
def test_write_parquet_chunk():
    # Setup mock S3
    s3 = boto3.client('s3', region_name='us-east-1')
    bucket = 'siem-data-test'
    s3.create_bucket(Bucket=bucket)
    
    # Sample JSON data from the user
    sample_rows = [
        {
            "timestamp": "2025-10-01T00:00:00.007Z",
            "request_id": "req-817c5681b4ae",
            "source_ip": "10.0.0.10",
            "status_code": 200
        },
        {
            "timestamp": "2025-10-01T00:00:00.019Z",
            "request_id": "req-a43d8fe655d2",
            "source_ip": "10.0.0.11",
            "status_code": 500
        }
    ]
    
    # Execute the chunk writer
    _write_parquet_chunk(
        bucket=bucket,
        original_prefix='raw/http-logs/',
        rows=sample_rows,
        chunk_index=0
    )
    
    # Verify the object was created in the correct processed/ prefix
    expected_key = 'processed/http-logs/chunk_00000.parquet'
    
    response = s3.list_objects_v2(Bucket=bucket, Prefix='processed/http-logs/')
    assert 'Contents' in response, "No objects found in processed/ prefix"
    assert len(response['Contents']) == 1
    assert response['Contents'][0]['Key'] == expected_key
    
    # Download the object and verify Parquet contents
    obj = s3.get_object(Bucket=bucket, Key=expected_key)
    from io import BytesIO
    buf = BytesIO(obj['Body'].read())
    
    table = pq.read_table(buf)
    assert table.num_rows == 2
    assert table.column_names == ['timestamp', 'request_id', 'source_ip', 'status_code']
    
    # Verify data types were inferred correctly
    df = table.to_pandas()
    assert df['status_code'].iloc[0] == 200
    assert df['source_ip'].iloc[1] == '10.0.0.11'
    print("All ingestion tests passed!")

if __name__ == "__main__":
    test_write_parquet_chunk()

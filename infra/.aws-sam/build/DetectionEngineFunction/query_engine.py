import os
import json
import duckdb

# Initialize DuckDB connection globally so it's reused across invocations
con = duckdb.connect(database=':memory:', read_only=False)

def setup_duckdb():
    """Configure DuckDB to use AWS credentials for S3 access."""
    # Install and load required extensions
    con.execute("INSTALL httpfs;")
    con.execute("LOAD httpfs;")
    con.execute("INSTALL aws;")
    con.execute("LOAD aws;")
    
    # Load AWS credentials from Lambda environment
    con.execute("CALL load_aws_credentials();")

def lambda_handler(event, context):
    """
    Executes an ad-hoc SQL query against the Parquet files in S3.
    Expects event payload: {"query": "SELECT * FROM 's3://bucket/processed/*/*.parquet' LIMIT 10"}
    """
    try:
        query = event.get('query')
        if not query:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing "query" parameter in event.'})
            }
        
        setup_duckdb()
        
        # Execute the query and fetch results as a list of dictionaries
        print(f"Executing query: {query}")
        result = con.execute(query).fetchdf()
        
        # Convert DataFrame to JSON serializable list of dicts
        # Note: In production with large result sets, consider streaming or paginating
        records = result.to_dict(orient='records')
        
        return {
            'statusCode': 200,
            'body': json.dumps(records, default=str) # default=str to handle dates/times
        }
        
    except Exception as e:
        print(f"Error executing query: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

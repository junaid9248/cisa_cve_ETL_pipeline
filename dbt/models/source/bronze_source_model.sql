WITH table_source AS (
    SELECT cveID,extracted_cve_record AS cve_json
    FROM {{ source('bronze','cve_raws_table') }}
)
SELECT
    
    JSON_VALUE(cve_json, '$.cve_id') AS cve_id,
    COALESCE(
        SAFE.PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%S.%f',JSON_VALUE(cve_json, '$.published_date')),
        SAFE.PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%S',JSON_VALUE(cve_json, '$.published_date')),
        SAFE.PARSE_TIMESTAMP('%Y-%m-%d',JSON_VALUE(cve_json, '$.published_date'))
    ) AS published_date,

    COALESCE(
        SAFE.PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%S.%f',JSON_VALUE(cve_json, '$.updated_date')),
        SAFE.PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%S',JSON_VALUE(cve_json, '$.updated_date')),
        SAFE.PARSE_TIMESTAMP('%Y-%m-%d',JSON_VALUE(cve_json, '$.updated_date'))
    ) AS updated_date,
    

from table_source
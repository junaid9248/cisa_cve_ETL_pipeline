{{ config(
    materialized='table',
    cluster_by=['updated_date']
) }}

WITH table_source AS (
    SELECT cveID,extracted_cve_record AS cve_json
    FROM {{ source('bronze','cve_raws_table') }}
)
SELECT
    
    -- Basic string value so JSON_VALUE is enough conversion
    cveID AS cve_id,
    
    -- Typecasting to a timestamp first and using COALESCE command to try-except
    -- Untill one format passes and is returned
    -- %F -> Standard format element in bigquery sql taht represents %Y-%m-%d
    -- E*%S -> Seconds with full fractional precision (a literal '*').
    -- SAFE allows that if one of them fails the query itself does not completely abort
    COALESCE(
        SAFE.PARSE_TIMESTAMP('%FT%H:%M:%E*S',JSON_VALUE(cve_json, '$.published_date')),
        SAFE.PARSE_TIMESTAMP('%FT%H:%M:%S',JSON_VALUE(cve_json, '$.published_date')),
        SAFE.PARSE_TIMESTAMP('%F',JSON_VALUE(cve_json, '$.published_date'))
    ) AS published_date,

    COALESCE(
        SAFE.PARSE_TIMESTAMP('%FT%H:%M:%E*S',JSON_VALUE(cve_json, '$.updated_date')),
        SAFE.PARSE_TIMESTAMP('%FT%H:%M:%S',JSON_VALUE(cve_json, '$.updated_date')),
        SAFE.PARSE_TIMESTAMP('%F',JSON_VALUE(cve_json, '$.updated_date'))
    ) AS updated_date,
    
    -- Casts string value to bool 
    -- Returns True if jsonvalue == true ; False if jsonvalue == false
    SAFE_CAST(JSON_VALUE(cve_json, '$.cisa_kev') AS BOOL) AS cisa_kev,
    -- PARSE_DATE(date_format-string, string_value) converts a string to date
    PARSE_DATE('%Y-%m-%d',JSON_VALUE(cve_json, '$.cisa_kev_date')) AS cisa_kev_date,

    SAFE_CAST(JSON_VALUE(cve_json ,'$.cvss_version') AS FLOAT64) AS cvss_version,
    SAFE_CAST(JSON_VALUE(cve_json, '$.base_score') AS FLOAT64) AS base_score,

    JSON_VALUE(cve_json, '$.attack_vector') AS attack_vector,
    JSON_VALUE(cve_json, '$.privileges_required') AS privileges_required,
    JSON_VALUE(cve_json, '$.user_interaction') AS user_interaction,
    JSON_VALUE(cve_json, '$.scope') AS scope,

    JSON_VALUE(cve_json, '$.confidentiality_impact') AS confidentiality_impact,
    JSON_VALUE(cve_json, '$.integrity_impact') AS integrity_impact,
    JSON_VALUE(cve_json, '$.availability_impact') AS availability_impact,

    COALESCE(
        SAFE.PARSE_TIMESTAMP('%FT%H:%M:%E*S',JSON_VALUE(cve_json, '$.ssvc_timestamp')),
        SAFE.PARSE_TIMESTAMP('%FT%H:%M:%S',JSON_VALUE(cve_json, '$.ssvc_timestamp')),
        SAFE.PARSE_TIMESTAMP('%F',JSON_VALUE(cve_json, '$.ssvc_timestamp'))
    ) AS ssvc_timestamp,
    
    JSON_VALUE(cve_json, '$.ssvc_exploitation') AS ssvc_exploitation,
    SAFE_CAST(JSON_VALUE(cve_json, '$.ssvc_automatable') AS BOOL) AS ssvc_automatable,
    JSON_VALUE(cve_json, '$.ssvc_technical_impact') AS ssvc_technical_impact,
    JSON_VALUE(cve_json, '$.ssvc_decision') AS ssvc_decision,

    JSON_VALUE_ARRAY(cve_json, '$.impacted_vendor') AS impacted_vendor,
    JSON_VALUE_ARRAY(cve_json, '$.impacted_products') AS impacted_products,
    JSON_VALUE_ARRAY(cve_json, '$.vulnerable_versions') AS vulnerable_versions,

    JSON_VALUE(cve_json, '$.cwe_number') AS cwe_number,
    JSON_VALUE(cve_json, '$.cwe_description') AS cwe_description,

FROM table_source



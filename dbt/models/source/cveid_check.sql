
SELECT cveId, extracted_cve_record, '$.cve_id' as test_cveID
FROM {{source('bronze', 'cve_raws_table')}}
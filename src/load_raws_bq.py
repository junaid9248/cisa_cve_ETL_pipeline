def extract_store_cve_data(self, year_data: Dict = {}, maxworkers: int = 50):
    year = year_data["year"]
    logging.info(f"Starting to process year data for {year}...")

    all_files = []
    for (subdir, files) in list(year_data["subdirs"].items()):
        all_files.extend(files)

    if not all_files:
        logging.warning(f"No files found for year {year}")
        return None

    max_workers = maxworkers
    factor = 5
    max_in_mem = max_workers * factor

    # one NDJSON output per year
    local_ndjson_path = f"/tmp/bronze_{year}.ndjson"
    if os.path.exists(local_ndjson_path):
        os.remove(local_ndjson_path)

    with open(local_ndjson_path, "w", encoding="utf-8") as out:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            pending = set()
            name_by_future = {}
            files_iter = iter(all_files)

            # prime
            while len(pending) < max_in_mem:
                try:
                    current_file = next(files_iter)
                except StopIteration:
                    break
                fut = executor.submit(self.extract_single_cve_file, file=current_file, year=year)
                pending.add(fut)
                name_by_future[fut] = current_file["name"]

            # drain
            while pending:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)

                for fut in done:
                    try:
                        bronze_row = fut.result()
                        if bronze_row:
                            out.write(json.dumps(bronze_row, ensure_ascii=False) + "\n")
                    except Exception as e:
                        logging.error(f"Failed to get record from {name_by_future.get(fut)}: {e}")
                    finally:
                        name_by_future.pop(fut, None)

                    try:
                        new_file = next(files_iter)
                        new_fut = executor.submit(self.extract_single_cve_file, file=new_file, year=year)
                        pending.add(new_fut)
                        name_by_future[new_fut] = new_file["name"]
                    except StopIteration:
                        pass

    # Upload that NDJSON to GCS (cloud mode only)
    if self.islocal is False:
        bucket = self.google_client.storage_client.bucket(self.google_client.bucket_name)
        gcs_object = f"bronze_ndjson/year={year}/bronze_{year}.ndjson"
        bucket.blob(gcs_object).upload_from_filename(local_ndjson_path)  # upload from file path [web:293]
        os.remove(local_ndjson_path)
        logging.info(f"Uploaded bronze NDJSON: gs://{self.google_client.bucket_name}/{gcs_object}")

    return None

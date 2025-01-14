import requests
import sqlite3
import json
from datetime import datetime, timezone, timedelta
from dateutil.parser import parse
from packaging.version import parse as parse_version
from packaging.specifiers import SpecifierSet
import logging
import time
import os
from typing import Optional, List, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class VulnerabilityTracker:
    def __init__(self, db_path: str = "vulnerabilities.db", api_key: Optional[str] = None):
        """Initialize the vulnerability tracker with database path and optional API key"""
        self.db_path = db_path
        self.api_key = api_key
        self.sleep_time = 6.1 
        self.start_date = "2023-01-01T00:00:00+03:00"
        self.end_date = "2024-12-31T23:59:59+03:00"
        self.init_database()

    def init_database(self):
        """Initialize the database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create metadata table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            ''')
            
            # Create new vulnerabilities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    package_name TEXT PRIMARY KEY,
                    vulnerable_versions TEXT NOT NULL,  -- JSON array of versions
                    osv_ranges TEXT,                    -- JSON array of range objects
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Initialize metadata if not exists
            cursor.execute('SELECT value FROM metadata WHERE key = "lastModEndDate"')
            result = cursor.fetchone()
            if not result:
                cursor.execute('INSERT INTO metadata (key, value) VALUES (?, ?)',
                             ("lastModEndDate", self.start_date))
            
            conn.commit()
            
    def get_last_mod_end_date(self) -> str:
        """Get the last modification end date from metadata"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM metadata WHERE key = "lastModEndDate"')
            result = cursor.fetchone()
            return result[0] if result else self.start_date
            
    def update_last_mod_end_date(self, end_date: str):
        """Update the last modification end date in metadata"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE metadata SET value = ? WHERE key = "lastModEndDate"',
                         (end_date,))
            conn.commit()

    def get_date_ranges(self, start_date: str, end_date: str) -> List[Tuple[str, str]]:
        """Break down date range into 120-day chunks because of the range filter limit"""
        start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        
        ranges = []
        current = start
        while current < end:
            range_end = min(current + timedelta(days=120), end)
            # Format with +03:00 timezone as it worked in curl
            ranges.append((
                current.strftime("%Y-%m-%dT%H:%M:%S.000+03:00"),
                range_end.strftime("%Y-%m-%dT%H:%M:%S.000+03:00")
            ))
            current = range_end
        
        return ranges
            
    def is_java_package(self, package: dict) -> tuple[bool, str, str]:
        """Check if a CPE item represents a Java package and return (is_java, package_name, package_version)"""
      
        cpe = package.get('cpe', {})

        cpe_name = cpe.get('cpeName', '').lower()

        # parse cpe name
        cpe_details = cpe_name.split(':')

        if cpe_details[2] != 'a':
            return False, "", ""
        
        package_name = cpe_details[4]
        package_version = cpe_details[5]

        # Terms that indicate it's not a Java package
        exclude_terms = {
            'javascript', 'node', 'npm', 'nodejs', 'typescript',
            'react', 'vue', 'angular', 'webpack', 'babel',
            'eslint', 'prettier', 'yarn', 'deno'
        }

        java_terms = {
            'java', 'jdk', 'jre', 'spring', 'hibernate', 'tomcat', 'maven',
            'gradle', 'jakarta', 'javax', 'jetty', 'jdbc', 'jpa', 'jms',
            'groovy', 'kotlin', 'scala'
        }

        # check if package name string contains any of the java terms
        if any(term in package_name for term in java_terms) and not any(term in package_name for term in exclude_terms):
            return True, package_name, package_version

        # Check product name
        product = cpe.get('product', {}).get('name', '').lower()
        if any(term in product for term in java_terms) and not any(term in product for term in exclude_terms):
            return True, package_name, package_version
            
        # Check titles
        titles = cpe.get('titles', [])
        title_text = ' '.join(t.get('title', '').lower() for t in titles)
        if any(term in title_text for term in java_terms) and not any(term in title_text for term in exclude_terms):
            return True, package_name, package_version
            
        return False, "", ""
            
    def try_get_osv_ranges(self, package_name: str, version: str) -> list:
        """Try to get vulnerability ranges from OSV for a given package and version.
        
        Args:
            package_name: Name of the package
            version: Version of the package
            
        Returns:
            List of ranges from OSV response. Empty list if no ranges found or error occurs.
        """
        osv_url = "https://api.osv.dev/v1/query"
        osv_payload = {
            "package": {
                "name": package_name,
            },
            "version": version
        }
        
        try:
            osv_response = requests.post(osv_url, json=osv_payload)
            osv_response.raise_for_status()
            osv_data = osv_response.json()
            
            all_ranges = []
            for vuln in osv_data.get('vulns', []):
                for affected in vuln.get('affected', []):
                    ranges = affected.get('ranges', [])
                    if ranges:
                        all_ranges.extend(ranges)
            
            return all_ranges
            
        except requests.RequestException as e:
            logging.error(f"Error querying OSV: {str(e)}")
            return []
            
    def fetch_missing_osv_ranges(self):
        """Process packages that don't have OSV ranges"""
        logging.info("Processing packages without OSV ranges...")
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT package_name, vulnerable_versions FROM vulnerabilities WHERE osv_ranges IS NULL')
            packages = cursor.fetchall()
            
            processed_count = 0
            ranges_found = 0
            
            for package_name, versions in packages:
                versions = json.loads(versions)
                for version in versions:
                    processed_count += 1
                    print(f"\nTrying to get OSV ranges for {package_name} {version}")
                    ranges = self.try_get_osv_ranges(package_name, version)
                    if ranges:
                        ranges_found += 1
                        print(f"\nFound OSV ranges for {package_name} {version}")
                        print(json.dumps(ranges, indent=2))
                        self.store_vulnerability(package_name, version, ranges)
            
            logging.info(f"Processed {processed_count} packages, found ranges for {ranges_found}")
            
    def fetch_nist_feed(self) -> Optional[dict]:
        """Fetch CPE data from NIST NVD for 2023-2024 period, filtering for Java packages"""
        base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        processed_count = 0
        java_count = 0
        
        # Get the last processed date from metadata
        start_date = self.get_last_mod_end_date()
        
        # If we've reached the end date, only process packages without OSV ranges
        if start_date >= self.end_date:
            logging.info("Up to date with end date, processing missing OSV ranges...")
            return self.fetch_missing_osv_ranges()
            
        date_ranges = self.get_date_ranges(start_date, self.end_date)
        
        for start_range, end_range in date_ranges:
            start_index = 0
            while True:
                params = {
                    "startIndex": start_index,
                    "lastModStartDate": start_range,
                    "lastModEndDate": end_range
                }
                
                try:
                    logging.info(f"Fetching CPEs (startIndex={start_index}, dateRange={start_range} to {end_range})")
                    request_start_time = time.time()
                    response = requests.get(base_url, params=params, headers=headers)
                    
                    if response.status_code == 403:
                        logging.error("Rate limit exceeded. Waiting 30 seconds before retry...")
                        time.sleep(30)
                        continue
                        
                    response.raise_for_status()
                    data = response.json()
                    
                    products = data.get('products', [])
                    if not products:
                        break
                        
                    # Process each package immediately
                    for product in products:
                        processed_count += 1
                        is_java, package_name, version = self.is_java_package(product)
                        if is_java:
                            java_count += 1
                            print(f"\nJava Package Found ({java_count}): {package_name}, Version: {version}")
                            
                            # Store package first
                            self.store_vulnerability(package_name, version)
                            
                            # Then try to get vulnerability ranges
                            ranges = self.try_get_osv_ranges(package_name, version)
                            if ranges:
                                print(f"\nOVS details found for package {package_name} {version}:")
                                self.store_vulnerability(package_name, version, ranges)
                    
                    total_results = data.get('totalResults', 0)
                    results_per_page = data.get('resultsPerPage', 0)
                    
                    logging.info(f"Processed {processed_count} CPEs, found {java_count} Java packages")
                    
                    elapsed_time = time.time() - request_start_time
                    sleep_time = max(self.sleep_time - elapsed_time, 0)
                    time.sleep(sleep_time)
                    
                except requests.RequestException as e:
                    logging.error(f"Error fetching NIST feed (startIndex={start_index}): {str(e)}")
                    if hasattr(e, 'response') and e.response:
                        logging.error(f"Status code: {e.response.status_code}")
                        logging.error(f"Response text: {e.response.text}")
                    return None
                    
                if total_results <= start_index + results_per_page:
                    # Update the last processed date after completing each chunk
                    self.update_last_mod_end_date(end_range)
                    break
                    
                start_index += results_per_page
                
    def store_vulnerability(self, package_name: str, version: str, ranges: list = None):
        """Store vulnerability information in the database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # First, try to get existing record
            cursor.execute('SELECT vulnerable_versions, osv_ranges FROM vulnerabilities WHERE package_name = ?',
                         (package_name,))
            result = cursor.fetchone()
            
            if result:
                # Update existing record
                versions = json.loads(result[0])
                if version not in versions:
                    versions.append(version)
                
                existing_ranges = json.loads(result[1]) if result[1] else []
                # Add new ranges if they don't exist and ranges is not None
                if ranges:
                    for range_obj in ranges:
                        if range_obj not in existing_ranges:
                            existing_ranges.append(range_obj)
                
                cursor.execute('''
                    UPDATE vulnerabilities 
                    SET vulnerable_versions = ?, 
                        osv_ranges = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE package_name = ?
                ''', (json.dumps(versions), json.dumps(existing_ranges) if existing_ranges else None, package_name))
            else:
                # Insert new record
                cursor.execute('''
                    INSERT INTO vulnerabilities 
                    (package_name, vulnerable_versions, osv_ranges)
                    VALUES (?, ?, ?)
                ''', (package_name, json.dumps([version]), json.dumps(ranges) if ranges else None))
            
            conn.commit()

    def update_database(self):
        """Update the vulnerability database with Java package vulnerabilities"""
        current_time = datetime.strptime("2025-01-14T14:34:03+03:00", "%Y-%m-%dT%H:%M:%S%z")
        current_time_str = current_time.strftime("%Y-%m-%dT%H:%M:%S.000+03:00")
        
        # Get last update time
        last_update = self.get_last_mod_end_date()
        
        if last_update:
            logging.info(f"Performing incremental update from {last_update} to {current_time_str}")
            feed_data = self.fetch_nist_feed()
        else:
            logging.info("Performing initial data population")
            feed_data = self.fetch_nist_feed()
        
        if not feed_data:
            return
            
        logging.info(f"Update completed. Processed {feed_data['total_processed']} CPEs, found {feed_data['java_packages']} Java packages")

def main():
    tracker = VulnerabilityTracker()
    tracker.update_database()

if __name__ == "__main__":
    main()

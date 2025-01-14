# Java Package Vulnerability Tracker

A tool for tracking vulnerabilities in Java packages by combining data from NIST's NVD (National Vulnerability Database) and OSV (Open Source Vulnerabilities).

## Installation

1. (Optional) Set up a virtual environment:

```bash
# Create virtual environment
python3 -m venv venv

# Activate on macOS/Linux
source venv/bin/activate

# Activate on Windows
# .\venv\Scripts\activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Set up environment variables (optional):

```bash
export NIST_API_KEY=your_api_key  # Only to avoid rate-limiting
```

## Usage

Run the script:

```bash
python vuln_tracker.py
```

The script will:

1. Initialize a SQLite database if it doesn't exist
2. Fetch vulnerabilities for Java packages from NIST within the specified date range
3. Query OSV for vulnerability ranges for each package and vulnerableversion
4. Store the results in the database
5. On subsequent runs, only fetch new or updated packages by this logic:

- Check the last processed date in the database (metadata table)
- Fetch vulnerabilities for packages updated since the last processed date
- In addition, check packages that don't have OSV ranges (in case added later)

## Decision-making process & known issues

I had to make assumptions to figure out a tanglible way to:

- Get the right vulnerabilities for Java packages. I tried very hard to find a way by just parsing cpeName but after test runs, I was either missing a lot of relevant indexes or getting irrelevant results.
- Figure out a way to map details returned from NIST to get details from OSV:
  - On that note, my extremely simple logic seems to be not working for most of of the vulnerabilities, since it rarely gets a OVS detail from a package name and version I provide from NIST result. If I remove the version filter, then there is no way keep loyal to the 2023/24 date range, since there is no date filter on OVS API. A smarter of version scoping might be a solution but that would require considirable amount of extra time, and I wanted to show what I could deliver in 3-4 hours time range for this task.
- It takes some time (with NIST API rate limiting) to process all items within the range, so the metadata info provides a fair continue mechanism (with some overwriting margin).
- When all CPEs are already indexed, recurring script runs should be much faster, but because of the problem of proper mapping from NIST results to OSV, most osv_range info are empty, and will be iterated on each run (After all NIST CPEs are indexed, if not, we will continue from the saved last processed date).
- I am well aware I made an assumtion by using last lastModStartDate & lastModEndDate filters to get feeds from 2023/2024 that might be a side-track.
- I intentionally committed db after a test run for you to see the results.

## Use of AI

Mostly for boilerplate code generation for DB operations, JSON parsing, filtering etc.
I also used Claude 3.5 (within Windsurf IDE) to get some technical info about CPE/CVE standards and OSV but I had to go through the docs myself, and so some experimental debug runs manually.

### Database Schema

The database uses SQLite with two main tables:

1. `metadata`: Tracks the last processed date

   - Enables incremental updates
   - Prevents redundant API calls

2. `vulnerabilities`: Stores package vulnerability information
   - `package_name` as PRIMARY KEY for efficient lookups
   - `vulnerable_versions` as JSON array for flexibility
   - `osv_ranges` as JSON for storing complex version range data
   - Timestamps for tracking record creation and updates

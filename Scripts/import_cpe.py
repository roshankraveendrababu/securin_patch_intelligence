import json
import requests
import re
from neo4j import GraphDatabase
import time

# Neo4j Configuration
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "123456789"

class CPEImporter:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.retry_limit = 5  # ✅ Increase retries for better coverage
        self.sleep_time = 5   # ✅ Increase delay to prevent API blocking

    def close(self):
        self.driver.close()

    def parse_cpe(self, cpe_uri):
        """Extract vendor, product, version, and other details from CPE name."""
        match = re.match(r"cpe:2\.3:[aho]:(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?):(.*?)$", cpe_uri)
        if match:
            return {
                "cpe_name": cpe_uri,
                "vendor": match.group(1),
                "product": match.group(2),
                "version": match.group(3),
                "update": match.group(4),
                "edition": match.group(5),
                "language": match.group(6),
                "sw_edition": match.group(7),
                "target_sw": match.group(8),
                "target_hw": match.group(9),
                "other": match.group(10)
            }
        else:
            return {"cpe_name": cpe_uri}

    def fetch_cpe_for_cve(self, cve_id):
        """Fetch CPEs directly from the NVD API for a given CVE ID with retries."""
        url = f"{self.nvd_api_url}?cveId={cve_id}"
        retries = 0

        while retries < self.retry_limit:
            try:
                response = requests.get(url, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    
                    cpe_list = []
                    for vuln in vulnerabilities:
                        configurations = vuln.get("cve", {}).get("configurations", [])
                        for config in configurations:
                            for node in config.get("nodes", []):
                                for cpe_match in node.get("cpeMatch", []):
                                    parsed_cpe = self.parse_cpe(cpe_match.get("criteria", ""))
                                    cpe_list.append(parsed_cpe)

                    return cpe_list

                elif response.status_code in [503, 429]:
                    print(f"⚠ API overloaded, retrying in {self.sleep_time} seconds... ({retries + 1}/{self.retry_limit})")
                    retries += 1
                    time.sleep(self.sleep_time)
                else:
                    print(f"⚠ Failed to fetch CPEs for {cve_id}: {response.status_code}")
                    return []

            except requests.exceptions.Timeout:
                print(f"⏳ Timeout while fetching CPEs for {cve_id}, retrying... ({retries + 1}/{self.retry_limit})")
                retries += 1
                time.sleep(self.sleep_time)
            except Exception as e:
                print(f"❌ Error fetching CPE data for {cve_id}: {e}")
                return []

        print(f"🚨 Skipping {cve_id} after {self.retry_limit} failed attempts.")
        return []

    def insert_cpes_into_neo4j(self, batch_size=50):
        """Fetch CVEs from Neo4j and map them to CPEs using NVD API (with batching)."""
        with self.driver.session() as session:
            result = session.run("MATCH (v:Vulnerability) RETURN v.vuln_id AS cve_id")
            cve_list = [record["cve_id"] for record in result]

            for i in range(0, len(cve_list), batch_size):
                batch = cve_list[i:i + batch_size]
                print(f"🔄 Processing batch {i+1} to {i+len(batch)} of {len(cve_list)}")

                for cve_id in batch:
                    cpe_data = self.fetch_cpe_for_cve(cve_id)
                    if not cpe_data:
                        print(f"⚠ No CPEs found for {cve_id}")
                        continue

                    for cpe in cpe_data:
                        print(f"✅ Inserting CPE: {cpe['cpe_name']} for CVE: {cve_id}")
                        session.run("""
                            MERGE (p:CPE {cpe_name: $cpe_name})
                            ON CREATE SET p.vendor = $vendor, p.product = $product, p.version = $version,
                                          p.update = $update, p.edition = $edition, p.language = $language,
                                          p.sw_edition = $sw_edition, p.target_sw = $target_sw, p.target_hw = $target_hw, p.other = $other
                            MERGE (v:Vulnerability {vuln_id: $cve_id})
                            MERGE (p)-[:AFFECTS]->(v)
                        """, cpe_name=cpe["cpe_name"], vendor=cpe.get("vendor", ""),
                             product=cpe.get("product", ""), version=cpe.get("version", ""),
                             update=cpe.get("update", ""), edition=cpe.get("edition", ""),
                             language=cpe.get("language", ""), sw_edition=cpe.get("sw_edition", ""),
                             target_sw=cpe.get("target_sw", ""), target_hw=cpe.get("target_hw", ""),
                             other=cpe.get("other", ""), cve_id=cve_id)

        print("✅ CPEs mapped and inserted successfully!")

if __name__ == "__main__":
    cpe_mapper = CPEImporter(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
    cpe_mapper.insert_cpes_into_neo4j()
    cpe_mapper.close()

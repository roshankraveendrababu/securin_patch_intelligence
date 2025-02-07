import requests
import concurrent.futures
from bs4 import BeautifulSoup
from neo4j import GraphDatabase

# Neo4j Configuration
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "123456789"

class PatchFinder:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def fetch_patches_bulk(self, cve_ids):
        """Fetch patches for multiple CVEs in one API call (NVD API)."""
        cve_query = "&cveId=".join(cve_ids)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_query}"
        patch_links = {}

        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    references = cve.get("references", [])
                    patch_links[cve_id] = [
                        ref["url"] for ref in references if "patch" in ref.get("url", "").lower()
                    ]
        except Exception as e:
            print(f"❌ NVD API failed: {e}")

        return patch_links

    def fetch_patch_from_redhat(self, cve_id):
        """Fetch patch from Red Hat security advisories."""
        url = f"https://access.redhat.com/security/cve/{cve_id}"
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            return [link['href'] for link in soup.find_all('a', href=True) if "patch" in link['href'].lower()]
        except:
            return []

    def fetch_patch_from_microsoft(self, cve_id):
        """Fetch patch from Microsoft security updates."""
        url = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return [url]
        except:
            return []

    def update_neo4j_with_patches(self):
        """Fetch all CVEs from Neo4j and link patches in bulk."""
        with self.driver.session() as session:
            result = session.run("MATCH (v:Vulnerability) RETURN v.vuln_id AS cve_id")
            cve_list = [record["cve_id"] for record in result]

        # **Step 1: Fetch patches in bulk from NVD API**
        patch_data = self.fetch_patches_bulk(cve_list[:50])  # Fetch first 50 CVEs in one go

        # **Step 2: Fetch patches from Microsoft & Red Hat using parallel processing**
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_redhat = {executor.submit(self.fetch_patch_from_redhat, cve): cve for cve in cve_list}
            future_microsoft = {executor.submit(self.fetch_patch_from_microsoft, cve): cve for cve in cve_list}

            for future in concurrent.futures.as_completed(future_redhat):
                cve = future_redhat[future]
                patch_data[cve] = patch_data.get(cve, []) + future.result()

            for future in concurrent.futures.as_completed(future_microsoft):
                cve = future_microsoft[future]
                patch_data[cve] = patch_data.get(cve, []) + future.result()

        # **Step 3: Store patches in Neo4j**
        with self.driver.session() as session:
            for cve_id, patches in patch_data.items():
                if not patches:
                    print(f"❌ No patch found for {cve_id}")
                    continue

                for patch_url in patches:
                    session.run("""
                        MERGE (p:Patch {patch_url: $patch_url})
                        MERGE (v:Vulnerability {vuln_id: $cve_id})
                        MERGE (p)-[:PATCHES]->(v)
                    """, patch_url=patch_url, cve_id=cve_id)

        print("✅ Patches linked successfully!")

if __name__ == "__main__":
    patch_finder = PatchFinder(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
    patch_finder.update_neo4j_with_patches()
    patch_finder.close()

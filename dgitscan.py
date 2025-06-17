import argparse
import requests
import re
import time
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from scanner_plugins.sensitive import (
    load_signatures,
    run_signature_engine,
    calculate_risk_score
)
import os
from dotenv import load_dotenv


console = Console()
SIGNATURES, SIGNATURE_WEIGHTS = load_signatures()

# ========== ARGUMENT PARSING ==========
parser = argparse.ArgumentParser(description="GitHub subdomain & sensitive data scanner")
parser.add_argument("-d", "--domain", required=True, help="Target domain to scan, e.g., example.com")
parser.add_argument("--silent", action="store_true", help="Run in silent mode without console output")
args = parser.parse_args()
TARGET_DOMAIN = args.domain.strip().lower()
IS_SILENT = args.silent

# ========== CONFIGURATION ==========
load_dotenv()  # Load environment variables from .env file
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # add your GitHub token to .env file or set it as an environment variable
if not GITHUB_TOKEN:
    console.print("[!] GITHUB_TOKEN not found. Please set it in your environment or .env file.", style="bold red")
    exit(1) 
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"}
KEYWORD = TARGET_DOMAIN
MAX_RESULTS = 50
DELAY = 6
THREAD_WORKERS = 5

# ========== REGEX DEFINITIONS ==========
escaped_domain = re.escape(TARGET_DOMAIN)
REGEXES = [
    rf"[a-zA-Z0-9\-\.]+\.{escaped_domain}(?=[^\w\-]|$)"
]

# Enhanced credential/query parameter regex
CREDENTIAL_QUERY_REGEX = re.compile(
    r"(?i)((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api\\.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn\\.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{8,64})['\"]",
    re.IGNORECASE
)

# ========== UTILITY FUNCTIONS ==========
def handle_rate_limit(response):
    remaining = int(response.headers.get("X-RateLimit-Remaining", 1))
    if remaining == 0:
        reset_time = int(response.headers.get("X-RateLimit-Reset", time.time() + 60))
        sleep_duration = reset_time - int(time.time()) + 1
        if not IS_SILENT:
            console.print(f"[!] Rate limit reached. Sleeping for {sleep_duration} seconds until reset...", style="bold yellow")
        time.sleep(max(sleep_duration, 1))

def search_github_code(query, page=1):
    url = f"https://api.github.com/search/code?q={query}&per_page=10&page={page}"
    resp = requests.get(url, headers=HEADERS)
    handle_rate_limit(resp)
    if resp.status_code == 200:
        return resp.json().get("items", [])
    elif resp.status_code == 403:
        console.print("[!] Rate limited or token expired.", style="bold red")
        exit()
    else:
        console.print(f"[!] Error {resp.status_code}: {resp.text}", style="bold red")
        return []

def get_raw_url(item):
    repo = item["repository"]["full_name"]
    path = item["path"]
    return f"https://raw.githubusercontent.com/{repo}/master/{path}"

def resolve_subdomain(subdomain):
    try:
        socket.gethostbyname(subdomain)
        return True
    except:
        return False

def scan_raw_file(raw_url, html_url):
    try:
        r = requests.get(raw_url, timeout=10)
        content = r.text.lower()
        subdomain_matches = []
        for pattern in REGEXES:
            subdomain_matches.extend(re.findall(pattern, content, flags=re.IGNORECASE))
        subdomain_matches = list(set(subdomain_matches)) if subdomain_matches else None

        sensitive_matches = run_signature_engine(content, SIGNATURES)
        risk_score = calculate_risk_score(sensitive_matches, SIGNATURE_WEIGHTS) if sensitive_matches else 0
        query_param_matches = re.findall(CREDENTIAL_QUERY_REGEX, content)

        result_entries = []
        if subdomain_matches:
            for sub in subdomain_matches:
                result_entry = {
                    "subdomain": sub,
                    "source": html_url or None,
                    "raw_url": raw_url or None,
                    "live": resolve_subdomain(sub)
                }
                if risk_score > 0:
                    result_entry["risk_score"] = risk_score
                    result_entry["leak_type"] = [s["type"] for s in sensitive_matches]
                    result_entry["leak_sample"] = [s["matches"] for s in sensitive_matches if s.get("matches")]
                if query_param_matches:
                    result_entry["query_params"] = [f"{k}={v}" for _, k, _, _, v in query_param_matches]
                result_entries.append(result_entry)
        return result_entries
    except Exception as e:
        if not IS_SILENT:
            console.print(f"[!] Failed to fetch {raw_url}: {e}", style="bold red")
        return []

results = []
if not IS_SILENT:
    console.print(f"\n[bold cyan]🚀 Starting GitHub scan for domain:[/] [bold green]{TARGET_DOMAIN}[/]\n")

for page in range(1, MAX_RESULTS // 10 + 1):
    items = search_github_code(KEYWORD, page)
    if not items:
        break
    with ThreadPoolExecutor(max_workers=THREAD_WORKERS) as executor:
        futures = {
            executor.submit(scan_raw_file, get_raw_url(item), item.get("html_url")): item
            for item in items
        }
        for future in as_completed(futures):
            entries = future.result()
            if entries:
                results.extend(entries)

if not IS_SILENT:
    console.print(f"\n[bold magenta]🎯 Found {len(results)} subdomains for '{TARGET_DOMAIN}':[bold magenta]")
    for r in results:
        panel_lines = [f"[bold]Subdomain:[/] {r['subdomain']}", f"[bold]Source:[/] {r['source']}"]
        if 'live' in r:
            panel_lines.append(f"[bold]Live:[/] {'✅' if r['live'] else '❌'}")
        if 'risk_score' in r:
            panel_lines.append(f"[bold yellow]Risk Score:[/] {r['risk_score']}")
            panel_lines.append(f"[bold red]Leak Types:[/] {', '.join(r['leak_type'])}")
            panel_lines.append(f"[bold blue]Example:[/] {', '.join([item for sublist in r['leak_sample'] for item in sublist][:3])}")
        if 'query_params' in r:
            panel_lines.append(f"[bold green]Query Leaks:[/] {', '.join(r['query_params'])}")
        console.print(Panel("\n".join(panel_lines), title="[green]Secret Detected[/]", expand=False))

output_dir = "output"
os.makedirs(output_dir, exist_ok=True)
output_file = os.path.join(output_dir, f"{TARGET_DOMAIN.replace('.', '_')}.json")
with open(output_file, "w") as f:
    json.dump(results, f, indent=4)

if not IS_SILENT:
    console.print(f"\n📁 [bold green]Results saved to:[/] {output_file}\n")

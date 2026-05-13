#!/usr/bin/env bash
set -euo pipefail

# =========================
# CONFIG
# =========================
PD_BIN="${HOME}/go/bin"
OUT_ROOT="${HOME}/hack-recon"

# Optional API keys (set these in your shell/profile if you have them)
: "${URLSIO_API_KEY:=}"
: "${URLSCAN_API_KEY:=}"
: "${OTX_API_KEY:=}"
: "${VT_API_KEY:=}"

domain=""
while getopts "d:" opt; do
  case "$opt" in
    d) domain="$OPTARG" ;;
  esac
done

if [ -z "$domain" ]; then
  echo "[!] Usage: $0 -d target.com"
  exit 1
fi

OUTDIR="${OUT_ROOT}/${domain}"
mkdir -p "${OUTDIR}"/{subdomains,live,urls,js,api,gf,idor,nuclei,nmap,msf,report,logs,tmp}

LOGFILE="${OUTDIR}/logs/run.log"

log() {
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  printf "[%s] %s\n" "$ts" "$1" | tee -a "$LOGFILE"
}

# =========================
# MODULE 1: SUBDOMAINS
# =========================
subdomains_subfinder() {
  log "Subdomains: subfinder..."
  "${PD_BIN}/subfinder" -d "${domain}" -silent -all \
    -o "${OUTDIR}/subdomains/subfinder.txt" 2>>"${LOGFILE}" || true
}

subdomains_assetfinder() {
  log "Subdomains: assetfinder..."
  if command -v assetfinder >/dev/null 2>&1; then
    assetfinder --subs-only "${domain}" \
      | sort -u > "${OUTDIR}/subdomains/assetfinder.txt" 2>>"${LOGFILE}" || true
  else
    : > "${OUTDIR}/subdomains/assetfinder.txt"
  fi
}

subdomains_crtsh() {
  log "Subdomains: crt.sh..."
  curl -s "https://crt.sh/?q=%25.${domain}&output=json" 2>>"${LOGFILE}" \
    | jq -r '.[].name_value' 2>/dev/null \
    | sed 's/\*\.//g' \
    | tr ' ' '\n' \
    | sort -u > "${OUTDIR}/subdomains/crtsh.txt" || true
}

subdomains_external_intel() {
  log "Subdomains: external intel (OTX, VT, URLScan)..."
  : > "${OUTDIR}/subdomains/external.txt"

  # OTX
  if [ -n "${OTX_API_KEY}" ]; then
    curl -s -H "X-OTX-API-KEY: ${OTX_API_KEY}" \
      "https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns" 2>>"${LOGFILE}" \
      | jq -r '.passive_dns[].hostname' 2>/dev/null \
      | sort -u >> "${OUTDIR}/subdomains/external.txt" || true
  fi

  # VirusTotal
  if [ -n "${VT_API_KEY}" ]; then
    curl -s --request GET \
      --url "https://www.virustotal.com/api/v3/domains/${domain}/subdomains?limit=1000" \
      --header "x-apikey: ${VT_API_KEY}" 2>>"${LOGFILE}" \
      | jq -r '.data[].id' 2>/dev/null \
      | sort -u >> "${OUTDIR}/subdomains/external.txt" || true
  fi

  # URLScan.io
  if [ -n "${URLSCAN_API_KEY}" ]; then
    curl -s -H "API-Key: ${URLSCAN_API_KEY}" \
      "https://urlscan.io/api/v1/search/?q=domain:${domain}" 2>>"${LOGFILE}" \
      | jq -r '.results[].page.domain' 2>/dev/null \
      | sort -u >> "${OUTDIR}/subdomains/external.txt" || true
  fi
}

subdomains_dnsx() {
  log "Subdomains: dnsx resolve..."
  cat "${OUTDIR}"/subdomains/*.txt 2>/dev/null \
    | sed 's/^\*\.//g' \
    | sort -u > "${OUTDIR}/subdomains/all_raw.txt"

  if [ -s "${OUTDIR}/subdomains/all_raw.txt" ]; then
    "${PD_BIN}/dnsx" -silent -resp-only -r 1.1.1.1,8.8.8.8 \
      -l "${OUTDIR}/subdomains/all_raw.txt" \
      -o "${OUTDIR}/subdomains/resolved.txt" 2>>"${LOGFILE}" || true
  else
    : > "${OUTDIR}/subdomains/resolved.txt"
  fi
}

subdomains_module() {
  subdomains_subfinder
  subdomains_assetfinder
  subdomains_crtsh
  subdomains_external_intel
  subdomains_dnsx
}

# =========================
# MODULE 2: LIVE HOSTS
# =========================
live_hosts_module() {
  log "Live hosts: httpx..."
  sort -u "${OUTDIR}/subdomains/resolved.txt" 2>/dev/null \
    | "${PD_BIN}/httpx" -silent -sc -title -tech-detect -ip -cname \
    -o "${OUTDIR}/live/live_with_status.txt" 2>>"${LOGFILE}" || true

  awk '{print $1}' "${OUTDIR}/live/live_with_status.txt" 2>/dev/null \
    | sort -u > "${OUTDIR}/live/live_hosts.txt" || true
}

# =========================
# MODULE 3: URL HARVESTING (ALL SOURCES)
# =========================
urls_gau() {
  log "URLs: gau..."
  : > "${OUTDIR}/urls/gau.txt"
  if [ -s "${OUTDIR}/live/live_hosts.txt" ]; then
    cat "${OUTDIR}/live/live_hosts.txt" \
      | gau --o "${OUTDIR}/urls/gau.txt" 2>>"${LOGFILE}" || true
  fi
}

urls_wayback() {
  log "URLs: waybackurls..."
  : > "${OUTDIR}/urls/wayback.txt"
  if [ -s "${OUTDIR}/live/live_hosts.txt" ]; then
    cat "${OUTDIR}/live/live_hosts.txt" \
      | waybackurls > "${OUTDIR}/urls/wayback.txt" 2>>"${LOGFILE}" || true
  fi
}

urls_katana() {
  log "URLs: katana..."
  : > "${OUTDIR}/urls/katana.txt"
  if [ -s "${OUTDIR}/live/live_hosts.txt" ]; then
    "${PD_BIN}/katana" -list "${OUTDIR}/live/live_hosts.txt" -silent \
      -o "${OUTDIR}/urls/katana.txt" 2>>"${LOGFILE}" || true
  fi
}

urls_waymore() {
  log "URLs: waymore (if installed)..."
  : > "${OUTDIR}/urls/waymore.txt"
  if command -v waymore >/dev/null 2>&1 && [ -s "${OUTDIR}/live/live_hosts.txt" ]; then
    while read -r h; do
      [ -z "$h" ] && continue
      waymore -i "$h" -mode U -oU "${OUTDIR}/tmp/waymore_tmp.txt" \
        >/dev/null 2>>"${LOGFILE}" || true
      cat "${OUTDIR}/tmp/waymore_tmp.txt" >> "${OUTDIR}/urls/waymore.txt" 2>/dev/null || true
      rm -f "${OUTDIR}/tmp/waymore_tmp.txt"
    done < "${OUTDIR}/live/live_hosts.txt"
  fi
}

urls_urlsio() {
  log "URLs: urls.io (API if key, else skip)..."
  : > "${OUTDIR}/urls/urlsio.txt"
  if [ -n "${URLSIO_API_KEY}" ]; then
    curl -s -H "Authorization: Bearer ${URLSIO_API_KEY}" \
      "https://urls.io/api/v1/urls?domain=${domain}&limit=10000" 2>>"${LOGFILE}" \
      | jq -r '.urls[].url' 2>/dev/null \
      | sort -u > "${OUTDIR}/urls/urlsio.txt" || true
  fi
}

urls_commoncrawl() {
  log "URLs: CommonCrawl..."
  : > "${OUTDIR}/urls/commoncrawl.txt"
  # Simple CC index query (may not always be complete)
  curl -s "https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.${domain}/*&output=json" 2>>"${LOGFILE}" \
    | jq -r '.url' 2>/dev/null \
    | sort -u > "${OUTDIR}/urls/commoncrawl.txt" || true
}

urls_urlscan() {
  log "URLs: URLScan.io..."
  : > "${OUTDIR}/urls/urlscan.txt"
  if [ -n "${URLSCAN_API_KEY}" ]; then
    curl -s -H "API-Key: ${URLSCAN_API_KEY}" \
      "https://urlscan.io/api/v1/search/?q=domain:${domain}" 2>>"${LOGFILE}" \
      | jq -r '.results[].page.url' 2>/dev/null \
      | sort -u > "${OUTDIR}/urls/urlscan.txt" || true
  fi
}

urls_otx() {
  log "URLs: OTX..."
  : > "${OUTDIR}/urls/otx.txt"
  if [ -n "${OTX_API_KEY}" ]; then
    curl -s -H "X-OTX-API-KEY: ${OTX_API_KEY}" \
      "https://otx.alienvault.com/api/v1/indicators/domain/${domain}/url_list?limit=5000&page=1" 2>>"${LOGFILE}" \
      | jq -r '.url_list[].url' 2>/dev/null \
      | sort -u > "${OUTDIR}/urls/otx.txt" || true
  fi
}

urls_virustotal() {
  log "URLs: VirusTotal..."
  : > "${OUTDIR}/urls/virustotal.txt"
  if [ -n "${VT_API_KEY}" ]; then
    curl -s --request GET \
      --url "https://www.virustotal.com/api/v3/domains/${domain}/urls?limit=1000" \
      --header "x-apikey: ${VT_API_KEY}" 2>>"${LOGFILE}" \
      | jq -r '.data[].attributes.url' 2>/dev/null \
      | sort -u > "${OUTDIR}/urls/virustotal.txt" || true
  fi
}

urls_archive_cdx() {
  log "URLs: Archive.org CDX..."
  : > "${OUTDIR}/urls/archive_cdx.txt"
  curl -s "http://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json&fl=original&collapse=urlkey" 2>>"${LOGFILE}" \
    | jq -r '.[].0' 2>/dev/null \
    | sort -u > "${OUTDIR}/urls/archive_cdx.txt" || true
}

urls_module_merge() {
  log "URLs: merging all sources..."
  cat "${OUTDIR}"/urls/*.txt 2>/dev/null \
    | sed 's/^\s*//g' \
    | sed 's/\s*$//g' \
    | grep -E '^https?://' 2>/dev/null \
    | sort -u > "${OUTDIR}/urls/all_urls.txt" || true
}

urls_module() {
  urls_gau
  urls_wayback
  urls_katana
  urls_waymore
  urls_urlsio
  urls_commoncrawl
  urls_urlscan
  urls_otx
  urls_virustotal
  urls_archive_cdx
  urls_module_merge
}

# =========================
# MODULE 4: JS INTELLIGENCE
# =========================
js_urls() {
  log "JS: extracting JS URLs..."
  if [ -s "${OUTDIR}/urls/all_urls.txt" ]; then
    grep -Ei '\.js(\?|$)' "${OUTDIR}/urls/all_urls.txt" \
      | sort -u > "${OUTDIR}/js/all_js_urls.txt" || true
  else
    : > "${OUTDIR}/js/all_js_urls.txt"
  fi
}

js_endpoints() {
  log "JS: extracting endpoints via katana..."
  if [ -s "${OUTDIR}/js/all_js_urls.txt" ]; then
    "${PD_BIN}/katana" -list "${OUTDIR}/js/all_js_urls.txt" -jsl -silent \
      -o "${OUTDIR}/js/js_endpoints.txt" 2>>"${LOGFILE}" || true
  else
    : > "${OUTDIR}/js/js_endpoints.txt"
  fi
}

js_module() {
  js_urls
  js_endpoints
}

# =========================
# MODULE 5: API MAPPING
# =========================
api_module() {
  log "API: extracting API endpoints..."
  {
    [ -s "${OUTDIR}/urls/all_urls.txt" ] && \
      grep -Ei '/api/|/v1/|/v2/|/v3/|/graphql|/rest/' "${OUTDIR}/urls/all_urls.txt" 2>/dev/null || true
    [ -s "${OUTDIR}/js/js_endpoints.txt" ] && \
      grep -Ei '/api/|/v1/|/v2/|/v3/|/graphql|/rest/' "${OUTDIR}/js/js_endpoints.txt" 2>/dev/null || true
  } | sort -u > "${OUTDIR}/api/all_api_endpoints.txt"
}

# =========================
# MODULE 6: GF PATTERNS
# =========================
gf_module() {
  log "GF: patterns (sqli, xss, lfi, redirect, ssrf, rce)..."
  if [ -s "${OUTDIR}/urls/all_urls.txt" ]; then
    gf sqli     < "${OUTDIR}/urls/all_urls.txt" > "${OUTDIR}/gf/sqli.txt"     2>>"${LOGFILE}" || true
    gf xss      < "${OUTDIR}/urls/all_urls.txt" > "${OUTDIR}/gf/xss.txt"      2>>"${LOGFILE}" || true
    gf lfi      < "${OUTDIR}/urls/all_urls.txt" > "${OUTDIR}/gf/lfi.txt"      2>>"${LOGFILE}" || true
    gf redirect < "${OUTDIR}/urls/all_urls.txt" > "${OUTDIR}/gf/redirect.txt" 2>>"${LOGFILE}" || true
    gf ssrf     < "${OUTDIR}/urls/all_urls.txt" > "${OUTDIR}/gf/ssrf.txt"     2>>"${LOGFILE}" || true
    gf rce      < "${OUTDIR}/urls/all_urls.txt" > "${OUTDIR}/gf/rce.txt"      2>>"${LOGFILE}" || true
  else
    : > "${OUTDIR}/gf/sqli.txt"
    : > "${OUTDIR}/gf/xss.txt"
    : > "${OUTDIR}/gf/lfi.txt"
    : > "${OUTDIR}/gf/redirect.txt"
    : > "${OUTDIR}/gf/ssrf.txt"
    : > "${OUTDIR}/gf/rce.txt"
  fi
}

# =========================
# MODULE 7: IDOR / BAC
# =========================
idor_module() {
  log "IDOR: extracting candidates..."
  if [ -s "${OUTDIR}/urls/all_urls.txt" ]; then
    grep -Ei 'id=|user=|uid=|account=|profile=|order=|invoice=' \
      "${OUTDIR}/urls/all_urls.txt" \
      | sort -u > "${OUTDIR}/idor/idor_candidates.txt" || true
  else
    : > "${OUTDIR}/idor/idor_candidates.txt"
  fi
}

# =========================
# MODULE 8: NUCLEI (OWASP-ALIGNED)
# =========================
nuclei_module() {
  log "Nuclei: hosts (OWASP-aligned tags)..."
  if [ -s "${OUTDIR}/live/live_hosts.txt" ]; then
    "${PD_BIN}/nuclei" -l "${OUTDIR}/live/live_hosts.txt" \
      -tags cve,misconfig,exposed-panel,exposed-admin,file-upload,rce,ssrf,xss,token,secret,info \
      -severity low,medium,high,critical \
      -o "${OUTDIR}/nuclei/hosts.txt" 2>>"${LOGFILE}" || true
  else
    : > "${OUTDIR}/nuclei/hosts.txt"
  fi

  log "Nuclei: urls (OWASP-aligned tags)..."
  if [ -s "${OUTDIR}/urls/all_urls.txt" ]; then
    "${PD_BIN}/nuclei" -l "${OUTDIR}/urls/all_urls.txt" \
      -tags cve,misconfig,file-upload,rce,ssrf,xss,token,secret,info \
      -severity low,medium,high,critical \
      -o "${OUTDIR}/nuclei/urls.txt" 2>>"${LOGFILE}" || true
  else
    : > "${OUTDIR}/nuclei/urls.txt"
  fi
}

# =========================
# MODULE 9: NMAP
# =========================
nmap_module() {
  log "Nmap: service + vuln scan..."
  if [ ! -s "${OUTDIR}/live/live_hosts.txt" ]; then
    log "Nmap: no live hosts."
    return 0
  fi

  ips=$(awk -F[/:] '{print $4}' "${OUTDIR}/live/live_hosts.txt" \
    | grep -E '^[0-9]+\.' | sort -u || true)

  [ -z "${ips}" ] && { log "Nmap: no IPs extracted."; return 0; }

  echo "${ips}" | xargs -r nmap -sV -sC -T4 -Pn \
    -oN "${OUTDIR}/nmap/top-ports-service.txt" 2>>"${LOGFILE}"
  echo "${ips}" | xargs -r nmap -sV --script vuln -T4 -Pn \
    -oN "${OUTDIR}/nmap/vuln-scan.txt" 2>>"${LOGFILE}"
}

# =========================
# MODULE 10: METASPLOIT (SAFE AUXILIARY SUITE)
# =========================
msf_module() {
  log "Metasploit: generating RC with full safe auxiliary suite..."
  rc="${OUTDIR}/msf/${domain}.rc"

  cat > "${rc}" <<EOF
workspace -a ${domain}
db_import ${OUTDIR}/nmap/top-ports-service.txt
db_import ${OUTDIR}/nmap/vuln-scan.txt

services
vulns

# HTTP / Web scanners (safe)
use auxiliary/scanner/http/http_version
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/robots_txt
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/ssl
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/title
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/open_proxy
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/dir_listing
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/cert
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/headers
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/cors
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/trace
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/options
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/files_dir
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

# CMS / framework enum (safe)
use auxiliary/scanner/http/wordpress_scanner
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/drupal_views
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/apache_userdir_enum
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

# SSL / TLS scanners (safe)
use auxiliary/scanner/ssl/ssl_version
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/ssl/ssl_cipher
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

# WebDAV / app servers (safe)
use auxiliary/scanner/http/webdav_scanner
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/tomcat_enum
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/jboss_enum
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/nginx_alias_traversal
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

# OWA / EWS (safe enum)
use auxiliary/scanner/http/owa_login
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

use auxiliary/scanner/http/owa_ews_enum
set RHOSTS file:${OUTDIR}/live/live_hosts.txt
run
back

services
vulns
EOF
}

# =========================
# MODULE 11: OWASP TOP 10 SUMMARY
# =========================
owasp_summary_module() {
  log "Report: OWASP Top 10 mapping..."
  sum="${OUTDIR}/report/${domain}-owasp-summary.md"
  {
    echo "# OWASP Top 10 Mapping for ${domain}"
    echo
    echo "This is a mapping aid for manual pentesting, based on recon + nuclei + Nmap + Metasploit auxiliary."
    echo
    echo "## A1: Injection"
    echo "- GF SQLi: gf/sqli.txt"
    echo "- GF RCE: gf/rce.txt"
    echo "- Nuclei injection/RCE-related findings: nuclei/hosts.txt, nuclei/urls.txt"
    echo
    echo "## A2: Broken Authentication"
    echo "- Login/auth endpoints in: api/all_api_endpoints.txt, urls/all_urls.txt"
    echo "- Metasploit HTTP info + CMS enum: msf/${domain}.rc"
    echo
    echo "## A3: Sensitive Data Exposure"
    echo "- Tokens/keys in JS: js/all_js_urls.txt, js/js_endpoints.txt"
    echo "- Nuclei info/token/secret templates: nuclei/*"
    echo "- SSL/TLS issues: nmap/*, Metasploit ssl_* modules"
    echo
    echo "## A4: XML External Entities (XXE)"
    echo "- XML/SOAP endpoints in: api/all_api_endpoints.txt, urls/all_urls.txt"
    echo "- Nuclei xxe/ssrf templates (if present in your template set)."
    echo
    echo "## A5: Broken Access Control (IDOR/BAC)"
    echo "- IDOR candidates: idor/idor_candidates.txt"
    echo "- Test manually with multiple roles/sessions."
    echo
    echo "## A6: Security Misconfiguration"
    echo "- Nuclei misconfig/exposed-panel/exposed-admin: nuclei/*"
    echo "- Nmap service/vuln: nmap/*"
    echo "- Metasploit HTTP/SSL scanners: msf/${domain}.rc"
    echo
    echo "## A7: Cross-Site Scripting (XSS)"
    echo "- GF XSS: gf/xss.txt"
    echo "- Nuclei XSS templates: nuclei/*"
    echo
    echo "## A8: Insecure Deserialization"
    echo "- Suspicious serialized params in: urls/all_urls.txt, api/all_api_endpoints.txt"
    echo "- Nuclei deserialization/RCE templates (if present)."
    echo
    echo "## A9: Using Components with Known Vulnerabilities"
    echo "- Nuclei CVE templates: nuclei/*"
    echo "- Nmap version detection: nmap/top-ports-service.txt"
    echo "- Metasploit service/version scanners: msf/${domain}.rc"
    echo
    echo "## A10: Insufficient Logging & Monitoring"
    echo "- Requires manual review of responses, error messages, and behavior."
  } > "${sum}"
}

# =========================
# MODULE 12: RECON REPORT
# =========================
recon_report_module() {
  log "Report: recon summary..."
  rpt="${OUTDIR}/report/${domain}-recon-report.md"
  {
    echo "# Recon Report for ${domain}"
    echo
    echo "## Subdomains"
    wc -l "${OUTDIR}/subdomains/resolved.txt" 2>/dev/null || echo "0"
    echo
    echo "## Live Hosts"
    wc -l "${OUTDIR}/live/live_hosts.txt" 2>/dev/null || echo "0"
    echo
    echo "## URLs"
    wc -l "${OUTDIR}/urls/all_urls.txt" 2>/dev/null || echo "0"
    echo
    echo "## JS Endpoints"
    wc -l "${OUTDIR}/js/js_endpoints.txt" 2>/dev/null || echo "0"
    echo
    echo "## API Endpoints"
    wc -l "${OUTDIR}/api/all_api_endpoints.txt" 2>/dev/null || echo "0"
    echo
    echo "## Nuclei Findings (hosts)"
    wc -l "${OUTDIR}/nuclei/hosts.txt" 2>/dev/null || echo "0"
    echo
    echo "## Nuclei Findings (urls)"
    wc -l "${OUTDIR}/nuclei/urls.txt" 2>/dev/null || echo "0"
    echo
    echo "## GF (sqli/xss/lfi/redirect/ssrf/rce)"
    wc -l "${OUTDIR}/gf/sqli.txt" "${OUTDIR}/gf/xss.txt" "${OUTDIR}/gf/lfi.txt" \
          "${OUTDIR}/gf/redirect.txt" "${OUTDIR}/gf/ssrf.txt" "${OUTDIR}/gf/rce.txt" 2>/dev/null || echo "0"
    echo
    echo "## IDOR Candidates"
    wc -l "${OUTDIR}/idor/idor_candidates.txt" 2>/dev/null || echo "0"
    echo
    echo "## Nmap"
    [ -f "${OUTDIR}/nmap/top-ports-service.txt" ] && echo "- Top ports: present" || echo "- Top ports: none"
    [ -f "${OUTDIR}/nmap/vuln-scan.txt" ] && echo "- Vuln scan: present" || echo "- Vuln scan: none"
    echo
    echo "## Metasploit"
    [ -f "${OUTDIR}/msf/${domain}.rc" ] && echo "- RC file: msf/${domain}.rc" || echo "- RC file: none"
  } > "${rpt}"
}

# =========================
# MAIN
# =========================
main() {
  log "Target: ${domain}"
  subdomains_module
  live_hosts_module
  urls_module
  js_module
  api_module
  gf_module
  idor_module
  nuclei_module
  nmap_module
  msf_module
  recon_report_module
  owasp_summary_module
  log "Done. Workspace: ${OUTDIR}"
  log "Next: load URLs, JS endpoints, API endpoints, GF hits, IDOR candidates, nuclei findings, and use msfconsole -r msf/${domain}.rc for auxiliary analysis."
}

main "$@"

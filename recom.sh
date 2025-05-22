#!/bin/bash

domain=$1

if [ -z "$domain" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

banner() {
    echo "======================================================"
    echo " ███╗   ██╗ ██████╗     █████╗  ██████╗████████╗███████╗"
    echo " ████╗  ██║██╔═══██╗   ██╔══██╗██╔════╝╚══██╔══╝██╔════╝"
    echo " ██╔██╗ ██║██║   ██║   ███████║██║        ██║   █████╗  "
    echo " ██║╚██╗██║██║   ██║   ██╔══██║██║        ██║   ██╔══╝  "
    echo " ██║ ╚████║╚██████╔╝██╗██║  ██║╚██████╗   ██║   ███████╗"
    echo " ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝"
    echo "======================================================"
    echo "      NG-APTF: Next-Gen Advanced PenTest Framework     "
    echo "======================================================"
}
banner

echo "[*] Creating output directories..."
mkdir -p recon_results/$domain/{subdomains,probed,extracted_urls,result}

# Step 1: Subdomain Enumeration (Mock for now)
echo "[*] Enumerating subdomains for $domain (fast)..."
echo "sieb-web1.$domain" >> recon_results/$domain/subdomains/subs.txt
echo "www.$domain" >> recon_results/$domain/subdomains/subs.txt

# Step 2: Live Host Probing
echo "[*] Probing live subdomains..."
cat recon_results/$domain/subdomains/subs.txt | httpx -silent > recon_results/$domain/probed/live.txt

# Step 3: URL Extraction (waybackurls + gau)
echo "[*] Extracting URLs (wayback & gau)..."
waybackurls $domain >> recon_results/$domain/extracted_urls/raw_urls.txt
gau $domain >> recon_results/$domain/extracted_urls/raw_urls.txt

# Clean duplicates
sort -u recon_results/$domain/extracted_urls/raw_urls.txt > recon_results/$domain/extracted_urls/final_urls.txt

# Step 4: XSS Patterns with GF and scan with Dalfox
echo "[*] Extracting XSS patterns using gf..."
gf xss < recon_results/$domain/extracted_urls/final_urls.txt > recon_results/$domain/extracted_urls/xss_candidates.txt

echo "[*] Scanning for XSS with Dalfox..."
cat recon_results/$domain/extracted_urls/xss_candidates.txt | dalfox pipe --format json --output recon_results/$domain/result/dalfox.json

# Step 5: Vulnerability scanning with Nuclei
echo "[*] Running Nuclei for general vulnerabilities..."
nuclei -l recon_results/$domain/extracted_urls/final_urls.txt -severity info,low,medium,high,critical -json -o recon_results/$domain/result/nuclei.json

# Final Summary Output
echo ""
echo "======================================================"
echo "[✔] Summary of Findings for $domain:"
echo "======================================================"

# Summary from Nuclei
if [[ -s recon_results/$domain/result/nuclei.json ]]; then
    echo "🔍 Nuclei Findings:"
    cat recon_results/$domain/result/nuclei.json | jq -r '"Title: \(.info.name)\nSeverity: \(.info.severity)\n---"'
else
    echo "✅ No vulnerabilities found by Nuclei."
fi

# Summary from Dalfox
if [[ -s recon_results/$domain/result/dalfox.json ]]; then
    echo "⚠️  XSS Findings (Dalfox):"
    cat recon_results/$domain/result/dalfox.json | jq -r '"Param: \(.param)\nPayload: \(.payload)\nType: \(.type)\n---"'
else
    echo "✅ No XSS issues found by Dalfox."
fi

echo "[✔] Recon finished for $domain. Results stored in recon_results/$domain/"


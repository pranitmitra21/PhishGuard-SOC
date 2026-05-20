import socket
import ssl
import dns.resolver
from datetime import datetime

def get_ssl_cert(domain: str, url: str = "") -> dict:
    # Speed fix: HTTP sites have no SSL — skip the connection attempt entirely.
    # Previously this would wait 3s for a refused connection on port 443.
    if url.startswith("http://"):
        return {"valid": False, "error": "HTTP site — no SSL"}

    # Speed fix: timeout reduced from 3s → 1.5s.
    # TLS handshakes complete in <300ms on modern infrastructure.
    # Phishing sites either have no SSL or respond quickly.
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=1.5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))

                return {
                    "valid": True,
                    "issuer": issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
                    "subject": subject.get('commonName', 'Unknown'),
                    "valid_from": cert.get('notBefore'),
                    "valid_to": cert.get('notAfter')
                }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def get_dns_records(domain: str) -> dict:
    records = {"A": [], "MX": [], "TXT": []}

    # Speed fix: explicit lifetime (seconds) per query.
    # Use reliable public DNS (Google/Cloudflare) to bypass slow local DNS timeouts.
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    resolver.lifetime = 3.0   # total time budget for all retries per query type

    try:
        answers = resolver.resolve(domain, 'A')
        for rdata in answers:
            records["A"].append(rdata.address)
    except Exception:
        pass

    try:
        answers = resolver.resolve(domain, 'MX')
        for rdata in answers:
            records["MX"].append(str(rdata.exchange))
    except Exception:
        pass
        
    try:
        answers = resolver.resolve(domain, 'TXT')
        for rdata in answers:
            records["TXT"].append(str(rdata))
    except Exception:
        pass

    return records

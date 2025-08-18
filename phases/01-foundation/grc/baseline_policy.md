# Baseline Security Policy (Phase 1)

**Purpose:** Establish minimum controls for the Enterprise Architecture Lab.

## Access Control
- SSH key-based auth required; passwords disabled where possible.
- Admin access restricted to designated IPs/subnets.
- Arkime viewer protected with authentication; TLS enforced.

## Crypto & TLS
- TLS 1.2+ (prefer 1.3) for all web services.
- Certificates issued by lab Intermediate CA; Root trusted on admin machines.
- Private keys stored with filesystem permissions 640 or stricter.

## Monitoring & Logging
- Zeek/Suricata/Arkime enabled on key segments.
- Logs retained for ≥30 days (lab); clock sync via NTP.

## Change Management
- All config changes via Git PRs (phases/*).
- GitHub Actions validates Terraform and checks SOC configs on each push.

## Hardening
- Elasticsearch restricted (loopback/VPN) or proxied with auth.
- Disable unused services (e.g., SMTP, default web pages) unless required.

## Incident Handling (lab)
- Capture artifacts (pcaps, logs), tag evidence, document timeline in repo under `incidents/`.

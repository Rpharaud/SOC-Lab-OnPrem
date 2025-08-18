# Control Mapping (Phase 1)

| NIST 800-53 Rev5 | ISO 27001:2022 Annex A | Control Intent | Phase 1 Implementation | Evidence |
|---|---|---|---|---|
| AC-2, AC-6 | A.5.15, A.8.2 | Account mgmt & least privilege | SSH keys-only, restricted admin subnets | `phases/01-foundation/soc/`, `baseline_policy.md` |
| AU-2, AU-6 | A.5.10, A.8.15 | Logging & monitoring | Zeek/Suricata/Arkime enabled | `phases/01-foundation/soc/**`, Arkime screenshots |
| CM-3, CM-5 | A.5.1, A.8.32 | Change & config mgmt | Git PRs + CI checks | Git history, Actions logs |
| IA-5 | A.5.17 | Authenticator mgmt | SSH keys, Arkime creds | README, Arkime user mgmt steps |
| SC-8, SC-12, SC-13 | A.8.24, A.8.24.1 | Crypto & TLS | Lab PKI; TLS 1.3 preferred | PKI tree, Arkime cert details |
| SI-4 | A.5.7 | System monitoring | Alerts & detections (Phase 3 later) | N/A (future phases) |

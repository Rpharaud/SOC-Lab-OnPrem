# Phase 1 – Red Team Baseline Attack Surface
_Date: 2025-08-16_  
_Subnet(s): 192.168.64.0/24_  
_Scanner: 192.168.64.10_  

## Targets discovered
- 192.168.64.10

## Service inventory (open TCP only)
| IP | Port/Proto | Service | Version |
|---|---|---|---|
| 192.168.64.10 | 22/tcp | ssh | OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0) |
| 192.168.64.10 | 25/tcp | smtp | Postfix smtpd |
| 192.168.64.10 | 80/tcp | http | Apache httpd 2.4.58 ((Ubuntu)) |
| 192.168.64.10 | 9200/tcp | ssl/wap-wsp? | - |

## High-level findings
- Arkime (8005/tcp) is **HTTPS** with lab PKI (Digest auth).
- Elasticsearch (9200/tcp) is **TLS + auth**; reachable from subnet (restrict).
- Apache (80/tcp) default page exposed.
- Postfix (25/tcp) reachable; disable/bind to localhost if not needed.

## Evidence files
- hosts: hosts_pingsweep.nmap / .gnmap
- tcp: tcp_services.nmap / .gnmap
- tls: tls_checks.nmap
- http: http_enums.nmap
- udp: udp_top20.nmap

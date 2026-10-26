# VPS options

Researched 26 October 2026. Prices change; check the provider's page before you buy.
**Choosing and paying is Saafir's call. Nothing has been bought or signed up for.**

Requirements: Ubuntu 24.04, 1 vCPU / 1 GB is enough (Cowrie + collector + Caddy
fit in ~800 MB of container limits), public IPv4, inbound 22/23 open, about $5/month.

## Shortlist

| | Vultr | Linode (Akamai) | OVHcloud US |
|---|---|---|---|
| Plan | Cloud Compute, 1 vCPU / 1 GB / 25 GB / 1 TB | Nanode 1 GB, 1 vCPU / 1 GB / 25 GB / 1 TB | VPS-1, 2 vCore / 4 GB / 40 GB NVMe, unmetered at 500 Mbps |
| Price | **$5.00/mo** ($0.007/hr) | **$5.00/mo** ($0.0075/hr) | **$4.54/mo** on a 12-month commitment (official); about $5.35 with no commitment (third-party figure, unverified) |
| IPv4 | Included | Included (standard; not checked in their docs) | Included |
| Billing | Hourly, capped monthly; delete any time | Hourly, capped monthly | Monthly, no hourly |
| Atlanta | Yes | Yes (us-southeast) | No (US sites, cities not listed) |
| Honeypot stance | AUP silent; prohibits outbound scanning and probing | AUP silent; prohibits pen-testing others without permission | ToS silent; prohibits unauthorised access and vulnerability testing of others |

### 1. Vultr: best fit

Exact spec, an Atlanta region, hourly billing so a teardown costs cents, and an
acceptable-use policy aimed at what your server does to others: "Unauthorized
port scanning, for any reason, is strictly prohibited." The egress lock in this
repo is what keeps the honeypot inside that line.
[AUP](https://www.vultr.com/legal/use-policy/) (modified 11 Mar 2026). Outbound SMTP is blocked by default.

### 2. Linode / Akamai: equivalent

Same shape and price, Atlanta available. Akamai's AUP (v7, effective 1 Aug 2026)
bars attacks on others' systems including "penetration testing or other
malicious activities" without permission, and allows immediate suspension for a
material violation. A passive honeypot is not pen-testing; outbound abuse would be.
[AUP PDF](https://www.akamai.com/site/en/documents/corporate/acceptable-use-policy.pdf).

### 3. OVHcloud US: most machine for the money

Twice the CPU and four times the RAM, unmetered traffic and anti-DDoS included.
Costs: monthly billing only, the lowest price needs a 12-month commitment, and
there is no Atlanta. [Terms](https://us.ovhcloud.com/legal/terms-of-service/).

## Ruled out (for now)

* **DigitalOcean**: $6/mo for 1 GB, and Atlanta is Premium-only. Its AUP requires
  prior written consent to "conduct any security or malware research", which a
  honeypot plausibly is. Usable only after a support ticket gets a written yes.
  [AUP](https://www.digitalocean.com/legal/acceptable-use-policy).
* **Hetzner Cloud**: excellent in the EU (CX23 €5.99) but US plans start around
  €17.99/mo, and its terms ban "scanning of foreign networks". Forum reports
  describe fast automated abuse tickets (unverified).

## Before buying, whichever you pick

* No provider names honeypots explicitly. A one-line support ticket ("I am
  running a low-interaction SSH honeypot for research; outbound traffic from the
  honeypot is blocked at the host firewall") gets a written record of their answer.
* No provider documents blocking inbound port 23, but this is unverified. Test it
  with `nc -vz <ip> 23` after deploy.
* Card or ID requirements at sign-up were not researched.

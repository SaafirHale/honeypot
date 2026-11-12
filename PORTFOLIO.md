# Portfolio entry (draft)

Draft for `saafirhale-site/src/content/projects.ts`, in the shape of its
`Project` type. Every claim below can be checked in this repository.

* `status` is `"live"` because the type defines it as "has a public link" (the repo).
  The sensor itself is not deployed yet. Add copy about real attack volumes only
  once it is, using numbers from the live stats.json, and add a dashboard link then.

```ts
{
  slug: "ssh-honeypot",
  category: "security",
  title: "SSH/Telnet Honeypot & Attack Dashboard",
  blurb:
    "Cowrie honeypot on a locked-down VPS, a collector that anonymises what it sees, and a public dashboard of attacks.",
  body: [
    "A Cowrie SSH and Telnet honeypot in Docker, built to sit on a public VPS and take the internet's background noise of credential-stuffing bots. Bots get an emulated shell; their logins, commands and uploaded files are logged and nothing they type ever executes.",
    "Containment came first. The container runs unprivileged on a read-only filesystem with CPU, memory and process limits, and a host firewall rule installed before Docker starts drops every connection that originates inside the honeypot network, so the sensor cannot be turned against anyone else. The real SSH daemon moves to a high port with key-only auth before the honeypot is allowed to bind port 22.",
    "A small Python collector with no network access turns Cowrie's logs into one statistics file: sessions per hour, source countries and networks from an offline GeoIP database, the credentials bots guess, the commands they run and the hashes of files they upload. Everything attacker-controlled is sanitised before publishing: addresses are cut to /24, links are defanged, and the collector refuses to write a file that still contains a full IP address. Captured malware never leaves the box.",
    "The dashboard is a static Next.js page that reads that file and renders it as plain text, so attacker-typed strings can't become markup on this site. A threat model, a runbook covering updates, compromise and teardown, and a cloud-init script for a fresh Ubuntu VPS ship with it.",
    "Running the full stack in Docker before deploying caught three deployment bugs and one that mattered more: the egress check reported \"blocked\" whenever its probe failed to run. It now fails closed, and the firewall rules have their own test that proves egress is open before the lock and dropped after it.",
  ],
  stack: ["Cowrie", "Docker", "Python", "iptables", "Next.js", "D3", "cloud-init", "Caddy"],
  links: [{ label: "Source", href: "https://github.com/SaafirHale/honeypot" }],
  status: "live",
}
```

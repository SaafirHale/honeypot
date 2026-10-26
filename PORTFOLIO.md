# Portfolio entry (draft)

Draft for `saafirhale-site/src/content/projects.ts`, in the shape of its
`Project` type. Every claim below can be checked in this repository. Two
fields are deliberately pending:

* `links`: empty until the repo is public (Saafir decides).
* `status`: `"personal"` while it runs only locally. Switch to `"live"` once the
  sensor is deployed and the dashboard is mounted, and only then add copy about
  real attack volumes, using numbers from the live stats.json.

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
  ],
  stack: ["Cowrie", "Docker", "Python", "iptables", "Next.js", "D3", "cloud-init", "Caddy"],
  links: [],
  status: "personal",
}
```

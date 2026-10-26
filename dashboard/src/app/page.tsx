import { HoneypotDashboard } from "@/components/honeypot/dashboard";
import { ThemeToggle } from "@/components/honeypot/theme-toggle";

// Where the collector's stats.json is served from. Defaults to the copy bundled in public/.
const STATS_URL =
  process.env.NEXT_PUBLIC_STATS_URL || `${process.env.NEXT_PUBLIC_BASE_PATH || ""}/stats.json`;

export default function HoneypotPage() {
  return (
    <div className="sh-wrap">
      <header className="hp-top">
        <span>
          <strong>Saafir Hale</strong> / honeypot
        </span>
        <ThemeToggle />
      </header>
      <main id="main">
        <section style={{ padding: "clamp(40px, 6vw, 80px) 0 0" }}>
          <p className="hp-eyebrow">Security · SSH/Telnet sensor</p>
          <h1 className="sh-h1">Honeypot</h1>
          <p className="sh-lede" style={{ marginTop: 24 }}>
            A Cowrie SSH and Telnet honeypot. Bots connect, guess passwords and run their scripts
            against an emulated shell. This page shows what they tried, aggregated and anonymised on
            the sensor before anything is published.
          </p>
        </section>
        <HoneypotDashboard src={STATS_URL} />
      </main>
    </div>
  );
}

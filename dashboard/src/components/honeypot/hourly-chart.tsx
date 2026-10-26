"use client";

import { useState } from "react";
import { fmt, type Hour, utcDay, utcShort } from "@/lib/stats";

const W = 1000;
const H = 180;
const GAP = 0.25; // fraction of each slot left as surface between bars

/** Sessions per hour for the last 168 hours. One series, so no legend: the heading names it. */
export function HourlyChart({ hours }: { hours: Hour[] }) {
  const [hover, setHover] = useState<number | null>(null);
  if (!hours.length) return <p className="hp-empty">No hourly data.</p>;

  const max = Math.max(1, ...hours.map((h) => h.sessions));
  const top = niceMax(max);
  const slot = W / hours.length;
  const barW = Math.max(1, slot * (1 - GAP));
  const peak = hours.reduce((a, h, i) => (h.sessions > hours[a].sessions ? i : a), 0);

  const dayStarts = hours
    .map((h, i) => ({ h, i }))
    .filter(({ h }) => h.t.endsWith("T00:00:00Z"));

  const hovered = hover === null ? null : hours[hover];

  return (
    <figure className="hp-chart" style={{ margin: 0 }}>
      <div className="hp-yaxis" aria-hidden="true">
        <span>{fmt(top)} sessions/h</span>
        <span>
          peak {fmt(hours[peak].sessions)} at {utcShort(hours[peak].t)} UTC
        </span>
      </div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`Sessions per hour over the last ${hours.length} hours. Peak ${hours[peak].sessions} at ${utcShort(hours[peak].t)} UTC.`}
        onMouseLeave={() => setHover(null)}
      >
        <line className="grid" x1={0} x2={W} y1={0} y2={0} />
        <line className="grid" x1={0} x2={W} y1={H / 2} y2={H / 2} />
        {dayStarts.map(({ i }) => (
          <line key={i} className="grid" x1={i * slot} x2={i * slot} y1={0} y2={H} />
        ))}
        {hours.map((h, i) => {
          const bh = (h.sessions / top) * H;
          return (
            <rect
              key={h.t}
              className="bar"
              data-dim={hover !== null && hover !== i}
              x={i * slot + (slot - barW) / 2}
              y={H - bh}
              width={barW}
              height={bh}
            />
          );
        })}
        <line className="base" x1={0} x2={W} y1={H} y2={H} />
        {/* Hit targets: the full column, not just the bar. */}
        {hours.map((h, i) => (
          <rect
            key={`hit-${h.t}`}
            x={i * slot}
            y={0}
            width={slot}
            height={H}
            fill="transparent"
            onMouseEnter={() => setHover(i)}
          />
        ))}
      </svg>
      {hovered && hover !== null && (
        <div
          className="hp-tip"
          style={{ left: `${((hover + 0.5) / hours.length) * 100}%`, top: 18 + H - (hovered.sessions / top) * H }}
        >
          {utcShort(hovered.t)} UTC · {fmt(hovered.sessions)} sessions · {fmt(hovered.logins)} logins
        </div>
      )}
      <div className="hp-ticks" aria-hidden="true">
        {dayStarts.map(({ h, i }) => (
          <span key={h.t} style={{ left: `${(i / hours.length) * 100}%` }}>
            {utcDay(h.t)}
          </span>
        ))}
      </div>
    </figure>
  );
}

function niceMax(n: number): number {
  const mag = 10 ** Math.floor(Math.log10(n));
  for (const m of [1, 2, 2.5, 5, 10]) {
    if (m * mag >= n) return m * mag;
  }
  return 10 * mag;
}

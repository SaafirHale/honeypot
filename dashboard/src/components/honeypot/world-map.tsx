"use client";

import { geoEqualEarth, geoPath } from "d3-geo";
import countries from "i18n-iso-countries";
import { useMemo, useState } from "react";
import { feature } from "topojson-client";
import type { GeometryCollection, Topology } from "topojson-specification";
import world from "world-atlas/countries-110m.json";
import { bucket, type Country, fmt, pct } from "@/lib/stats";

const W = 960;
const H = 470;

type Shape = { id: string; name: string; d: string; cx: number; cy: number };

// Projected once at module load: the geography never changes, only the fill.
function buildShapes(): Shape[] {
  const topo = world as unknown as Topology<{ countries: GeometryCollection<{ name: string }> }>;
  const fc = feature(topo, topo.objects.countries);
  const projection = geoEqualEarth().fitExtent([[4, 4], [W - 4, H - 4]], fc);
  const path = geoPath(projection);
  return fc.features
    .filter((f) => f.properties?.name !== "Antarctica")
    .map((f) => {
      const [cx, cy] = path.centroid(f);
      return { id: String(f.id ?? ""), name: f.properties?.name ?? "", d: path(f) ?? "", cx, cy };
    });
}

let cached: Shape[] | null = null;

/** Sessions by source country (single-hue sequential, log scale). The table below is the accessible view. */
export function WorldMap({ data, total }: { data: Country[]; total: number }) {
  const shapes = useMemo(() => (cached ??= buildShapes()), []);
  const [hover, setHover] = useState<Shape | null>(null);

  const byNumeric = useMemo(() => {
    const m = new Map<string, Country>();
    for (const c of data) {
      const n = countries.alpha2ToNumeric(c.code);
      if (n) m.set(n, c);
    }
    return m;
  }, [data]);

  const max = Math.max(0, ...data.filter((c) => c.code !== "ZZ").map((c) => c.sessions));
  const hovered = hover ? byNumeric.get(hover.id) : undefined;

  return (
    <div className="hp-map">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="World map of sessions by source country"
        onMouseLeave={() => setHover(null)}>
        {shapes.map((s) => {
          const c = byNumeric.get(s.id);
          return (
            <path key={s.id + s.name} d={s.d} data-b={bucket(c?.sessions ?? 0, max)}
              onMouseEnter={() => setHover(s)} />
          );
        })}
      </svg>
      {hover && (
        <div className="hp-tip" style={{ left: `${(hover.cx / W) * 100}%`, top: `${(hover.cy / H) * 100}%` }}>
          {hovered ? hovered.name : hover.name} ·{" "}
          {hovered ? `${fmt(hovered.sessions)} sessions (${pct(hovered.sessions, total)})` : "none"}
        </div>
      )}
      <div className="hp-legend" aria-hidden="true">
        <span>fewer</span>
        {[1, 2, 3, 4, 5].map((b) => (
          <i key={b} data-b={b} />
        ))}
        <span>more sessions (log scale)</span>
      </div>
    </div>
  );
}

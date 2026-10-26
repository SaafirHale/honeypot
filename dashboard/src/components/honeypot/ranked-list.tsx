import { fmt } from "@/lib/stats";

export type Row = { key: string; label: string; note?: string; value: number };

/** Top-N as a hairline list with a thin bar per row. The numbers are the table view. */
export function RankedList({ title, rows, unit, limit = 10 }: {
  title: string;
  rows: Row[];
  unit: string;
  limit?: number;
}) {
  const shown = rows.slice(0, limit);
  const max = Math.max(1, ...shown.map((r) => r.value));
  return (
    <section className="hp-list" aria-label={title}>
      <h3>{title}</h3>
      {shown.length === 0 ? (
        <p className="hp-empty">Nothing recorded in this window.</p>
      ) : (
        <ol>
          {shown.map((r) => (
            <li key={r.key} title={`${r.label}: ${fmt(r.value)} ${unit}`}>
              <span className="k">
                {r.label}
                {r.note ? <small>{r.note}</small> : null}
              </span>
              <span className="v">{fmt(r.value)}</span>
              <span className="track" aria-hidden="true">
                <span className="fill" style={{ display: "block", width: `${(r.value / max) * 100}%` }} />
              </span>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

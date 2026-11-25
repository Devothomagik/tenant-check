import { txt } from "./dns";

export type SpfHop = {
  mechanism: string;
  target: string;
  cost: number;
  depth: number;
  error?: string;
};
export type SpfResult = {
  record: string | null;
  multiple: boolean;
  lookups: number;
  hops: SpfHop[];
  qualifier: "-all" | "~all" | "?all" | "+all" | "none";
};

const LOOKUP = /^[+\-~?]?(include:|a(:|\/|$)|mx(:|\/|$)|exists:|ptr(:|$)|redirect=)/i;

export const countsAsLookup = (term: string) => LOOKUP.test(term);

async function walk(
  domain: string,
  depth: number,
  hops: SpfHop[],
  seen: Set<string>,
): Promise<number> {
  if (depth > 10 || seen.has(domain)) return 0;
  seen.add(domain);
  const rec = (await txt(domain)).find((t) => /^v=spf1(\s|$)/i.test(t));
  if (!rec) return 0;
  let total = 0;
  for (const term of rec.split(/\s+/).slice(1)) {
    if (!countsAsLookup(term)) continue;
    const t = term.replace(/^[+\-~?]/, "");
    const m = t.match(/^(include:|redirect=)(.+)$/i);
    if (m && m[2]) {
      const idx = hops.length;
      hops.push({ mechanism: m[1]!.replace(/[:=]$/, ""), target: m[2], cost: 1, depth });
      const nested = await walk(m[2], depth + 1, hops, seen);
      const hop = hops[idx]!;
      hop.cost = 1 + nested;
      total += 1 + nested;
    } else {
      hops.push({
        mechanism: t.split(/[:/]/)[0]!,
        target: t.includes(":") ? t.split(":")[1]! : domain,
        cost: 1,
        depth,
      });
      total += 1;
    }
  }
  return total;
}

export async function analyzeSpf(domain: string): Promise<SpfResult> {
  const recs = (await txt(domain)).filter((t) => /^v=spf1(\s|$)/i.test(t));
  const record = recs[0] ?? null;
  const hops: SpfHop[] = [];
  const lookups = record ? await walk(domain, 0, hops, new Set()) : 0;
  const q = record?.match(/\s([+\-~?]?)all\b/i);
  const qualifier = !q ? "none" : (((q[1] || "+") + "all") as SpfResult["qualifier"]);
  return { record, multiple: recs.length > 1, lookups, hops, qualifier };
}

export function parseTags(rec: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of rec.split(";")) {
    const [k, ...v] = part.split("=");
    if (k && v.length) out[k.trim().toLowerCase()] = v.join("=").trim();
  }
  return out;
}

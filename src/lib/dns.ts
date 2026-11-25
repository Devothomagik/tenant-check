// Browser DNS-over-HTTPS (Cloudflare supports CORS for application/dns-json).
export type DnsAnswer = { name: string; type: number; TTL: number; data: string };
export type DnsResult = { status: number; answers: DnsAnswer[] };

const TYPE = { A: 1, CNAME: 5, MX: 15, TXT: 16 } as const;
export type RRType = keyof typeof TYPE;

const cache = new Map<string, Promise<DnsResult>>();

export function doh(name: string, type: RRType): Promise<DnsResult> {
  const key = `${name}|${type}`;
  const hit = cache.get(key);
  if (hit) return hit;
  const p = fetch(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    {
      headers: { accept: "application/dns-json" },
    },
  )
    .then((r) => r.json() as Promise<{ Status: number; Answer?: DnsAnswer[] }>)
    .then((j) => ({ status: j.Status, answers: j.Answer ?? [] }))
    .catch(() => ({ status: -1, answers: [] as DnsAnswer[] }));
  cache.set(key, p);
  return p;
}

export const txtOf = (a: DnsAnswer) => a.data.replace(/^"|"$/g, "").replace(/"\s*"/g, "");

export async function txt(name: string): Promise<string[]> {
  const r = await doh(name, "TXT");
  return r.answers.filter((a) => a.type === TYPE.TXT).map(txtOf);
}

export async function cname(name: string): Promise<string | null> {
  const r = await doh(name, "CNAME");
  const a = r.answers.find((x) => x.type === TYPE.CNAME);
  return a ? a.data.replace(/\.$/, "") : null;
}

export async function mx(name: string): Promise<{ pref: number; host: string }[]> {
  const r = await doh(name, "MX");
  return r.answers
    .filter((a) => a.type === TYPE.MX)
    .map((a) => {
      const [p, h] = a.data.split(/\s+/);
      return { pref: Number(p), host: (h ?? "").replace(/\.$/, "") };
    })
    .sort((a, b) => a.pref - b.pref);
}

/** Any record (CNAME or A) resolves for name. */
export async function resolves(name: string): Promise<string | null> {
  const c = await cname(name);
  if (c) return c;
  const r = await doh(name, "A");
  const a = r.answers.find((x) => x.type === TYPE.A);
  return a ? a.data : null;
}

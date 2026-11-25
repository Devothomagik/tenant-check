import { cname, mx, resolves, txt } from "./dns";
import { analyzeSpf, parseTags, type SpfResult } from "./spf";
import type { MsProbe } from "./ms-probe";

export type Status = "PASS" | "WARN" | "MISSING" | "INFO";

export type ScanResult = {
  domain: string;
  at: string;
  ms: MsProbe | null;
  msError: string | null;
  dkim: { s1: string | null; s2: string | null; initialTenant: string | null };
  spf: SpfResult;
  dmarc: {
    record: string | null;
    p: string | null;
    sp: string | null;
    pct: string | null;
    rua: string | null;
  };
  mx: { records: { pref: number; host: string }[]; gateway: string };
  intune: { registration: string | null; enrollment: string | null };
  autodiscover: string | null;
  mtaSts: string | null;
  tlsRpt: string | null;
};

export function gatewayOf(hosts: string[]): string {
  const h = hosts.join(" ").toLowerCase();
  if (!hosts.length) return "None";
  if (h.includes("mail.protection.outlook.com")) return "Exchange Online";
  if (h.includes("pphosted.com") || h.includes("ppe-hosted.com")) return "Proofpoint";
  if (h.includes("mimecast")) return "Mimecast";
  if (h.includes("google.com") || h.includes("googlemail.com")) return "Google Workspace";
  if (h.includes("barracudanetworks")) return "Barracuda";
  if (h.includes("iphmx.com")) return "Cisco Secure Email";
  return "Third-party / self-hosted";
}

export function initialTenantFrom(target: string | null): string | null {
  // selector1-contoso-com._domainkey.contoso.onmicrosoft.com  -> contoso.onmicrosoft.com
  const m = target?.match(/_domainkey\.([a-z0-9-]+\.onmicrosoft\.com)/i);
  return m?.[1]?.toLowerCase() ?? null;
}

async function probe(domain: string): Promise<MsProbe> {
  const r = await fetch(`/api/probe?domain=${encodeURIComponent(domain)}`);
  if (!r.ok) throw new Error(`/api/probe HTTP ${r.status}`);
  return (await r.json()) as MsProbe;
}

export async function runScan(domain: string): Promise<ScanResult> {
  const msP = probe(domain).then(
    (ms) => ({ ms, err: null as string | null }),
    (e: unknown) => ({ ms: null, err: e instanceof Error ? e.message : "probe failed" }),
  );
  const [s1, s2, spf, dmarcTxt, mxs, reg, enr, auto, sts, rpt, msR] = await Promise.all([
    cname(`selector1._domainkey.${domain}`),
    cname(`selector2._domainkey.${domain}`),
    analyzeSpf(domain),
    txt(`_dmarc.${domain}`),
    mx(domain),
    resolves(`enterpriseregistration.${domain}`),
    resolves(`enterpriseenrollment.${domain}`),
    resolves(`autodiscover.${domain}`),
    txt(`_mta-sts.${domain}`),
    txt(`_smtp._tls.${domain}`),
    msP,
  ]);
  const dm = dmarcTxt.find((t) => /^v=DMARC1/i.test(t)) ?? null;
  const tags = dm ? parseTags(dm) : {};
  return {
    domain,
    at: new Date().toISOString(),
    ms: msR.ms,
    msError: msR.err,
    dkim: { s1, s2, initialTenant: initialTenantFrom(s1) ?? initialTenantFrom(s2) },
    spf,
    dmarc: {
      record: dm,
      p: tags["p"] ?? null,
      sp: tags["sp"] ?? null,
      pct: tags["pct"] ?? null,
      rua: tags["rua"] ?? null,
    },
    mx: { records: mxs, gateway: gatewayOf(mxs.map((m) => m.host)) },
    intune: { registration: reg, enrollment: enr },
    autodiscover: auto,
    mtaSts: sts.find((t) => /^v=STSv1/i.test(t)) ?? null,
    tlsRpt: rpt.find((t) => /^v=TLSRPTv1/i.test(t)) ?? null,
  };
}

export function cliFor(d: string): string {
  return [
    `curl -s https://login.microsoftonline.com/${d}/v2.0/.well-known/openid-configuration | jq '{issuer,tenant_region_scope,cloud_instance_name}'`,
    `curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@${d}&json=1" | jq '{NameSpaceType,FederationBrandName,AuthURL}'`,
    `dig +short CNAME selector1._domainkey.${d}`,
    `dig +short CNAME selector2._domainkey.${d}`,
    `dig +short TXT ${d} | grep -i spf1`,
    `dig +short TXT _dmarc.${d}`,
    `dig +short MX ${d}`,
    `dig +short CNAME enterpriseregistration.${d}`,
    `dig +short CNAME enterpriseenrollment.${d}`,
    `dig +short CNAME autodiscover.${d}`,
    `dig +short TXT _mta-sts.${d}`,
    `dig +short TXT _smtp._tls.${d}`,
  ].join("\n");
}

export function spfStatus(s: SpfResult): Status {
  if (!s.record) return "MISSING";
  if (s.lookups > 10 || s.multiple || s.qualifier === "+all" || s.qualifier === "none")
    return "MISSING";
  if (s.lookups >= 9 || s.qualifier === "?all") return "WARN";
  return "PASS";
}

export function dmarcStatus(p: string | null): Status {
  if (!p) return "MISSING";
  if (p === "none") return "WARN";
  return "PASS";
}

export function toMarkdown(r: ScanResult): string {
  const L = (k: string, v: string | null | undefined) => `| ${k} | \`${v ?? "—"}\` |`;
  return [
    `# TenantProbe — ${r.domain}`,
    `_${r.at}_`,
    "",
    "| Field | Value |",
    "|---|---|",
    L("Tenant ID", r.ms?.oidc.tenantId),
    L("Region Scope", r.ms?.oidc.region),
    L("Cloud Instance", r.ms?.oidc.cloud),
    L("Auth Namespace", r.ms?.realm.namespace),
    L("Federation AuthURL", r.ms?.realm.authUrl),
    L("DKIM selector1", r.dkim.s1),
    L("DKIM selector2", r.dkim.s2),
    L("Initial Tenant", r.dkim.initialTenant),
    L("SPF", r.spf.record),
    L("SPF Lookups", `${r.spf.lookups} / 10`),
    L("SPF Qualifier", r.spf.qualifier),
    L("DMARC", r.dmarc.record),
    L("MX Gateway", r.mx.gateway),
    L("MX", r.mx.records.map((m) => `${m.pref} ${m.host}`).join(", ")),
    L("enterpriseregistration", r.intune.registration),
    L("enterpriseenrollment", r.intune.enrollment),
    L("autodiscover", r.autodiscover),
    L("_mta-sts", r.mtaSts),
    L("_smtp._tls", r.tlsRpt),
  ].join("\n");
}

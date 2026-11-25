import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import {
  cliFor,
  dmarcStatus,
  runScan,
  spfStatus,
  toMarkdown,
  type ScanResult,
  type Status,
} from "@/lib/scan";
import { DOMAIN_RE } from "@/lib/ms-probe";
import { Button } from "@/components/ui/button";
import { Check, Copy } from "lucide-react";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "TenantProbe — M365, Entra ID & DNS posture inspector" },
      {
        name: "description",
        content:
          "Passive Entra ID tenant, federation, DKIM, SPF, DMARC, MX and MTA-STS inspection for any domain.",
      },
      { property: "og:title", content: "TenantProbe" },
      {
        property: "og:description",
        content:
          "Passive Entra ID tenant, federation, DKIM, SPF, DMARC, MX and MTA-STS inspection.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: Index,
});

const PILLS = ["microsoft.com", "github.com", "canada.ca"];

function useCopy() {
  const [k, setK] = useState<string | null>(null);
  const copy = useCallback((text: string, key: string) => {
    void navigator.clipboard.writeText(text);
    setK(key);
    setTimeout(() => setK((c) => (c === key ? null : c)), 1200);
  }, []);
  return { copied: k, copy };
}

const badgeTone: Record<Status, string> = {
  PASS: "text-muted-foreground",
  WARN: "text-warn",
  MISSING: "text-fail",
  INFO: "text-muted-foreground",
};

function Badge({ s, label }: { s: Status; label?: string }) {
  return (
    <span
      className={`inline-flex min-h-6 max-w-full items-center font-mono text-xs leading-4 ${badgeTone[s]}`}
    >
      {label
        ? label.replace(/\b[A-Z]{2,}\b/g, (word) =>
            ["DNS", "SPF", "DKIM", "DMARC", "CLI", "JSON"].includes(word)
              ? word
              : word.toLowerCase(),
          )
        : s.toLowerCase()}
    </span>
  );
}

function CopyBtn({
  text,
  id,
  copy,
  copied,
}: { text: string; id: string } & ReturnType<typeof useCopy>) {
  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={() => copy(text, id)}
      aria-label={copied === id ? "Copied" : "Copy " + id}
      title={copied === id ? "Copied" : "Copy"}
      className="h-8 w-8 shrink-0 text-muted-foreground hover:text-foreground"
    >
      {copied === id ? <Check strokeWidth={1.5} /> : <Copy strokeWidth={1.5} />}
    </Button>
  );
}

function Row({
  label,
  value,
  status,
  badge,
  fix,
  children,
  c,
  id,
}: {
  label: string;
  value?: ReactNode | undefined;
  status?: Status;
  badge?: string;
  fix?: string | undefined;
  children?: ReactNode;
  c: ReturnType<typeof useCopy>;
  id: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="probe-row border-t border-border px-4 py-3 first:border-t-0">
      <div className="probe-fields">
        <div className="probe-label text-xs leading-5 text-muted-foreground">{label}</div>
        <div className="probe-value min-w-0 font-mono text-[13px] leading-5 tabular-nums">
          {value ?? <span className="text-muted-foreground">—</span>}
        </div>
        <div className="probe-status flex items-start justify-end gap-2">
          {fix && (status === "WARN" || status === "MISSING") && (
            <Button
              onClick={() => setOpen((o) => !o)}
              variant="ghost"
              size="sm"
              className="h-8 px-2 text-xs text-muted-foreground hover:text-foreground"
            >
              {open ? "Hide fix" : "Show fix"}
            </Button>
          )}
          {status && <Badge s={status} {...(badge ? { label: badge } : {})} />}
        </div>
      </div>
      {children && <div className="probe-details">{children}</div>}
      {open && fix && (
        <div className="mt-2 flex items-start gap-3 border border-border bg-background p-3">
          <pre className="min-w-0 flex-1 whitespace-pre-wrap [overflow-wrap:anywhere] font-mono text-[12px] text-foreground">
            {fix}
          </pre>
          <CopyBtn text={fix} id={`fix-${id}`} {...c} />
        </div>
      )}
    </div>
  );
}

function Panel({
  n,
  title,
  children,
  wide,
}: {
  n: number;
  title: string;
  children: ReactNode;
  wide?: boolean;
}) {
  return (
    <section className={`probe-panel bg-card ${wide ? "md:col-span-2" : ""}`}>
      <header className="flex items-center gap-2 border-b border-border px-4 py-3">
        <span className="font-mono text-xs text-muted-foreground tabular-nums">{n}</span>
        <h2 className="text-[15px] font-semibold leading-5">{title}</h2>
      </header>
      {children}
    </section>
  );
}

function Meter({ n }: { n: number }) {
  const tone = n > 10 ? "bg-fail" : n >= 9 ? "bg-warn" : "bg-pass";
  return (
    <div className="mt-2 flex gap-0.5">
      {Array.from({ length: 10 }, (_, i) => (
        <div key={i} className={`h-1.5 flex-1 ${i < n ? tone : "bg-muted"}`} />
      ))}
    </div>
  );
}

function Index() {
  const [input, setInput] = useState("microsoft.com");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<"grid" | "raw">("grid");
  const [tab, setTab] = useState<"json" | "cli">("cli");
  const [hopsOpen, setHopsOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const c = useCopy();

  const inspect = useCallback(async (raw: string) => {
    const d = raw
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .replace(/\/.*$/, "")
      .replace(/^.*@/, "");
    if (!DOMAIN_RE.test(d)) {
      setError(`invalid domain: ${d || "(empty)"}`);
      return;
    }
    setError(null);
    setInput(d);
    setLoading(d);
    try {
      setResult(await runScan(d));
    } catch (e) {
      setError(e instanceof Error ? e.message : "scan failed");
    } finally {
      setLoading(null);
    }
  }, []);

  useEffect(() => {
    inputRef.current?.focus();
    void inspect("microsoft.com");
  }, [inspect]);

  const r = result;
  const d = r?.domain ?? "contoso.com";
  const ms = r?.ms;
  const managed = ms?.realm.namespace === "Managed";
  const federated = ms?.realm.namespace === "Federated";
  const dkimOk = !!(r?.dkim.s1 && r.dkim.s2);
  const spfS = r ? spfStatus(r.spf) : "INFO";
  const dmS = r ? dmarcStatus(r.dmarc.p) : "INFO";
  const tenantSlug = r?.dkim.initialTenant?.split(".")[0] ?? "contoso";
  const dash = d.replace(/\./g, "-");

  return (
    <div className="flex min-h-screen flex-col">
      <div className="flex min-h-14 flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3">
        <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
          <span className="font-mono text-base font-medium">TenantProbe</span>
          {loading && (
            <span className="font-mono text-xs text-muted-foreground">resolving {loading}…</span>
          )}
          {!loading && r && (
            <span className="font-mono text-xs text-muted-foreground tabular-nums">
              {r.at.replace("T", " ").slice(0, 19)}Z
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            disabled={!r}
            onClick={() => r && c.copy(toMarkdown(r), "md")}
            variant="outline"
            size="sm"
            className="h-8 px-3 text-xs shadow-none"
          >
            {c.copied === "md" ? "Copied" : "Copy report"}
          </Button>
          <Button
            onClick={() => setView((v) => (v === "grid" ? "raw" : "grid"))}
            variant="outline"
            size="sm"
            aria-pressed={view === "raw"}
            className={`h-8 px-3 text-xs shadow-none ${view === "raw" ? "bg-accent" : ""}`}
          >
            Raw JSON / CLI
          </Button>
        </div>
      </div>

      <div className="border-b border-border px-4 py-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void inspect(input);
          }}
          className="flex border border-border bg-card focus-within:border-ring"
        >
          <span className="flex items-center pl-3 font-mono text-sm text-muted-foreground">$</span>
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            aria-label="Domain"
            placeholder="Domain"
            spellCheck={false}
            autoCapitalize="off"
            className="h-11 min-w-0 flex-1 bg-transparent px-3 font-mono text-sm outline-none placeholder:text-muted-foreground"
          />
          <Button
            type="submit"
            disabled={!!loading}
            className="h-11 rounded-none border-l border-border px-5 text-[13px] shadow-none"
          >
            Inspect
          </Button>
        </form>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          {PILLS.map((p) => (
            <Button
              key={p}
              onClick={() => void inspect(p)}
              variant="ghost"
              size="sm"
              className={`h-8 border border-border px-2 font-mono text-xs ${r?.domain === p ? "bg-accent text-foreground" : "text-muted-foreground"}`}
            >
              {p}
            </Button>
          ))}
          {error && <span className="ml-2 font-mono text-xs text-fail">{error}</span>}
        </div>
      </div>

      <main
        className={`flex-1 transition-opacity duration-150 motion-reduce:transition-none ${loading ? "opacity-50" : ""}`}
      >
        {view === "raw" || !r ? (
          r ? (
            <RawView r={r} tab={tab} setTab={setTab} c={c} />
          ) : (
            <div className="p-4 font-mono text-[13px] text-muted-foreground">resolving…</div>
          )
        ) : (
          <div className="grid grid-cols-1 gap-px border-b border-border bg-border md:grid-cols-2">
            <Panel n={1} title="Entra ID / OIDC tenant">
              <Row
                c={c}
                id="tid"
                label="Tenant ID"
                status={ms?.oidc.tenantId ? "PASS" : "MISSING"}
                badge={ms?.oidc.tenantId ? "FOUND" : "NO TENANT"}
                value={
                  ms?.oidc.tenantId ? (
                    <span className="flex min-w-0 items-start gap-2">
                      <span className="min-w-0 flex-1">{ms.oidc.tenantId}</span>
                      <CopyBtn text={ms.oidc.tenantId} id="tid" {...c} />
                    </span>
                  ) : r.msError ? (
                    <span className="text-fail">{r.msError}</span>
                  ) : undefined
                }
              />
              <Row c={c} id="reg" label="Region scope" value={ms?.oidc.region} />
              <Row c={c} id="cloud" label="Cloud instance" value={ms?.oidc.cloud} />
              <Row
                c={c}
                id="iss"
                label="Issuer"
                value={<span className="text-muted-foreground">{ms?.oidc.issuer ?? "—"}</span>}
              />
            </Panel>

            <Panel n={2} title="Identity & federation (GetUserRealm)">
              <Row
                c={c}
                id="ns"
                label="Auth namespace"
                status={managed ? "PASS" : federated ? "WARN" : "INFO"}
                badge={
                  managed
                    ? "MANAGED"
                    : federated
                      ? "FEDERATED"
                      : (ms?.realm.namespace ?? "UNKNOWN").toUpperCase()
                }
                value={
                  managed
                    ? "Managed (cloud-native)"
                    : federated
                      ? "Federated (external IdP / ADFS)"
                      : ms?.realm.namespace
                }
              />
              <Row c={c} id="brand" label="Federation brand" value={ms?.realm.brand} />
              <Row c={c} id="auth" label="Federation endpoint" value={ms?.realm.authUrl} />
              <Row c={c} id="proto" label="Protocol" value={ms?.realm.federationProtocol} />
            </Panel>

            <Panel n={3} title="M365 initial tenant & DKIM">
              <Row
                c={c}
                id="dkim"
                label="M365 DKIM status"
                status={dkimOk ? "PASS" : "MISSING"}
                badge={dkimOk ? "ENABLED" : "MISSING"}
                value={
                  dkimOk ? (
                    "selector1 + selector2 CNAMEs resolve"
                  ) : (
                    <span className="text-fail">Outbound M365 mail not DKIM-signed with {d}</span>
                  )
                }
                fix={`selector1._domainkey.${d}  CNAME  selector1-${dash}._domainkey.${tenantSlug}.onmicrosoft.com\nselector2._domainkey.${d}  CNAME  selector2-${dash}._domainkey.${tenantSlug}.onmicrosoft.com\n\n# Exchange Online PowerShell\nNew-DkimSigningConfig -DomainName ${d} -Enabled $true\nSet-DkimSigningConfig -Identity ${d} -Enabled $true`}
              />
              <Row c={c} id="s1" label="selector1" value={r.dkim.s1} />
              <Row c={c} id="s2" label="selector2" value={r.dkim.s2} />
              <Row c={c} id="init" label="Initial tenant domain" value={r.dkim.initialTenant} />
            </Panel>

            <Panel n={4} title="SPF lookups & DMARC">
              <Row
                c={c}
                id="spf"
                label="SPF lookup counter"
                status={spfS}
                badge={!r.spf.record ? "MISSING" : r.spf.lookups > 10 ? "PERMERROR" : spfS}
                value={r.spf.record ? `${r.spf.lookups} / 10 DNS lookups` : undefined}
                fix={
                  r.spf.record && r.spf.lookups > 10
                    ? `# Flatten or remove includes to get <= 10 lookups\n${r.spf.record}`
                    : `${d}  TXT  "v=spf1 include:spf.protection.outlook.com -all"`
                }
              >
                {r.spf.record && (
                  <div className="min-w-0">
                    <Meter n={r.spf.lookups} />
                    <div className="mt-2 [overflow-wrap:anywhere] font-mono text-[12px] text-muted-foreground">
                      {r.spf.record}
                    </div>
                    {r.spf.hops.length > 0 && (
                      <Button
                        onClick={() => setHopsOpen((o) => !o)}
                        variant="ghost"
                        size="sm"
                        className="mt-2 h-8 px-0 font-mono text-xs text-muted-foreground hover:bg-transparent hover:text-foreground"
                      >
                        {hopsOpen ? "−" : "+"} {r.spf.hops.length} lookup terms
                      </Button>
                    )}
                    {hopsOpen && (
                      <div className="mt-1 border border-border font-mono text-[12px] tabular-nums">
                        {r.spf.hops.map((h, i) => (
                          <div
                            key={i}
                            className="flex justify-between border-t border-border px-2 py-1 first:border-t-0"
                          >
                            <span style={{ paddingLeft: h.depth * 16 }}>
                              <span className="text-muted-foreground">{h.mechanism}</span>{" "}
                              {h.target}
                            </span>
                            <span className="text-muted-foreground">{h.cost}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </Row>
              <Row
                c={c}
                id="q"
                label="SPF qualifier"
                status={
                  !r.spf.record
                    ? "INFO"
                    : r.spf.qualifier === "-all"
                      ? "PASS"
                      : r.spf.qualifier === "~all"
                        ? "WARN"
                        : "MISSING"
                }
                badge={r.spf.record ? r.spf.qualifier.toUpperCase() : "—"}
                value={r.spf.record ? r.spf.qualifier : undefined}
                fix={r.spf.record ? r.spf.record.replace(/\s[+~?]?all\b/i, " -all") : undefined}
              />
              <Row
                c={c}
                id="dmarc"
                label="DMARC enforcement"
                status={dmS}
                badge={
                  dmS === "WARN"
                    ? "MONITORING ONLY (p=none)"
                    : dmS === "PASS"
                      ? `p=${r.dmarc.p}`.toUpperCase()
                      : "MISSING"
                }
                value={
                  r.dmarc.record ? (
                    <span className="grid grid-cols-[auto_1fr] gap-x-3">
                      <span className="text-muted-foreground">p</span>
                      <span>{r.dmarc.p}</span>
                      <span className="text-muted-foreground">sp</span>
                      <span>{r.dmarc.sp ?? "—"}</span>
                      <span className="text-muted-foreground">pct</span>
                      <span>{r.dmarc.pct ?? "100"}</span>
                      <span className="text-muted-foreground">rua</span>
                      <span>{r.dmarc.rua ?? "—"}</span>
                    </span>
                  ) : undefined
                }
                fix={`_dmarc.${d}  TXT  "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@${d}"`}
              >
                {dmS === "WARN" && (
                  <div className="mt-2 font-mono text-[12px] text-warn">
                    Spoofed mail failing SPF/DKIM is still delivered to recipient inboxes.
                  </div>
                )}
              </Row>
            </Panel>

            <Panel n={5} title="Service records & transport security" wide>
              <div className="grid grid-cols-1 md:grid-cols-2">
                <div className="md:border-r md:border-border">
                  <Row
                    c={c}
                    id="mx"
                    label="MX gateway"
                    status={r.mx.records.length ? "INFO" : "MISSING"}
                    badge={r.mx.gateway.toUpperCase()}
                    value={
                      r.mx.records.length ? (
                        <span className="block">
                          {r.mx.records.map((m) => (
                            <span key={m.host} className="block">
                              <span className="text-muted-foreground">{m.pref}</span> {m.host}
                            </span>
                          ))}
                        </span>
                      ) : undefined
                    }
                    fix={`${d}  MX  0  ${dash}.mail.protection.outlook.com`}
                  />
                  <Row
                    c={c}
                    id="adisc"
                    label="Autodiscover"
                    status={r.autodiscover ? "PASS" : "MISSING"}
                    value={r.autodiscover}
                    fix={`autodiscover.${d}  CNAME  autodiscover.outlook.com`}
                  />
                </div>
                <div>
                  <Row
                    c={c}
                    id="ereg"
                    label="enterpriseregistration"
                    status={r.intune.registration ? "PASS" : "MISSING"}
                    value={r.intune.registration}
                    fix={`enterpriseregistration.${d}  CNAME  enterpriseregistration.windows.net`}
                  />
                  <Row
                    c={c}
                    id="eenr"
                    label="enterpriseenrollment"
                    status={r.intune.enrollment ? "PASS" : "MISSING"}
                    value={r.intune.enrollment}
                    fix={`enterpriseenrollment.${d}  CNAME  enterpriseenrollment-s.manage.microsoft.com`}
                  />
                  <Row
                    c={c}
                    id="sts"
                    label="MTA-STS"
                    status={r.mtaSts ? "PASS" : "MISSING"}
                    value={r.mtaSts}
                    fix={`_mta-sts.${d}  TXT  "v=STSv1; id=${new Date().toISOString().slice(0, 10).replace(/-/g, "")}01"\n# + https://mta-sts.${d}/.well-known/mta-sts.txt\nversion: STSv1\nmode: enforce\nmx: *.mail.protection.outlook.com\nmax_age: 604800`}
                  />
                  <Row
                    c={c}
                    id="rpt"
                    label="TLS-RPT"
                    status={r.tlsRpt ? "PASS" : "MISSING"}
                    value={r.tlsRpt}
                    fix={`_smtp._tls.${d}  TXT  "v=TLSRPTv1; rua=mailto:tlsrpt@${d}"`}
                  />
                </div>
              </div>
            </Panel>

            <section className="bg-card md:col-span-2">
              <header className="flex items-center justify-between border-b border-border px-4 py-2">
                <h2 className="text-[13px] font-medium leading-5">CLI equivalent</h2>
                <CopyBtn text={cliFor(d)} id="cli" {...c} />
              </header>
              <pre className="overflow-x-auto px-4 py-3 font-mono text-[12px] leading-relaxed text-muted-foreground">
                {cliFor(d)}
              </pre>
            </section>
          </div>
        )}
      </main>

      <footer className="grid grid-cols-1 border-t border-border font-mono text-xs text-muted-foreground sm:grid-cols-3">
        <div className="border-border px-4 py-3 sm:border-r">Passive posture inspector</div>
        <div className="border-t border-border px-4 py-3 sm:border-t-0 sm:border-r">
          Public OIDC discovery & DNS-over-HTTPS
        </div>
        <div className="border-t border-border px-4 py-3 sm:border-t-0">Zero domains logged</div>
      </footer>
    </div>
  );
}

function RawView({
  r,
  tab,
  setTab,
  c,
}: {
  r: ScanResult;
  tab: "json" | "cli";
  setTab: (t: "json" | "cli") => void;
  c: ReturnType<typeof useCopy>;
}) {
  const text = tab === "json" ? JSON.stringify(r, null, 2) : cliFor(r.domain);
  return (
    <div className="bg-card">
      <div className="flex items-center justify-between border-b border-border px-4">
        <div className="flex">
          {(["cli", "json"] as const).map((t) => (
            <Button
              key={t}
              onClick={() => setTab(t)}
              variant="ghost"
              className={`h-10 rounded-none border-b px-3 font-mono text-xs ${tab === t ? "border-foreground text-foreground" : "border-transparent text-muted-foreground"}`}
            >
              {t === "cli" ? "CLI" : "JSON"}
            </Button>
          ))}
        </div>
        <CopyBtn text={text} id={`raw-${tab}`} {...c} />
      </div>
      <pre className="overflow-x-auto p-4 font-mono text-[12px] leading-relaxed">{text}</pre>
    </div>
  );
}

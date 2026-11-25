// Server-side Microsoft endpoint probe (no CORS on getuserrealm). Shared by the /api/scan route.
export const DOMAIN_RE =
  /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;

export type MsProbe = {
  oidc: {
    ok: boolean;
    status: number;
    tenantId: string | null;
    region: string | null;
    cloud: string | null;
    issuer: string | null;
  };
  realm: {
    ok: boolean;
    namespace: string | null;
    brand: string | null;
    authUrl: string | null;
    federationProtocol: string | null;
  };
};

async function getJson(
  url: string,
): Promise<{ status: number; body: Record<string, unknown> | null }> {
  try {
    const r = await fetch(url, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(8000),
    });
    const t = await r.text();
    try {
      return { status: r.status, body: JSON.parse(t) as Record<string, unknown> };
    } catch {
      return { status: r.status, body: null };
    }
  } catch {
    return { status: 0, body: null };
  }
}

const s = (v: unknown) => (typeof v === "string" && v ? v : null);

export async function probeMicrosoft(domain: string): Promise<MsProbe> {
  const d = encodeURIComponent(domain);
  const [o, r] = await Promise.all([
    getJson(`https://login.microsoftonline.com/${d}/v2.0/.well-known/openid-configuration`),
    getJson(`https://login.microsoftonline.com/getuserrealm.srf?login=user@${d}&json=1`),
  ]);
  const issuer = s(o.body?.["issuer"]);
  const tenantId =
    issuer?.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i)?.[0] ?? null;
  return {
    oidc: {
      ok: !!tenantId,
      status: o.status,
      tenantId,
      region: s(o.body?.["tenant_region_scope"]),
      cloud: s(o.body?.["cloud_instance_name"]),
      issuer,
    },
    realm: {
      ok: !!r.body,
      namespace: s(r.body?.["NameSpaceType"]),
      brand: s(r.body?.["FederationBrandName"]),
      authUrl: s(r.body?.["AuthURL"]),
      federationProtocol: s(r.body?.["federation_protocol"]),
    },
  };
}

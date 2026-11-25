# TenantProbe

Passive, read-only inspection of any domain's Microsoft 365 / Entra ID and email-authentication posture.

For authorized security assessments only; it only reads public DNS and public endpoints.

Enter a domain and TenantProbe reports:

- **Entra ID / OIDC** — tenant ID, region, cloud and issuer from the public OpenID discovery document
- **Identity & federation** — managed vs. federated namespace, brand name, federation endpoint (`getuserrealm`)
- **Microsoft 365** — initial `onmicrosoft.com` tenant, DKIM `selector1` / `selector2`
- **SPF & DMARC** — recursive SPF lookup counter (RFC 7208 limit of 10), DMARC enforcement level
- **Service records** — MX gateway, Intune enrollment/registration, Autodiscover, MTA-STS, TLS-RPT

Every row shows PASS / WARN / MISSING with a copyable fix, plus the equivalent `dig` / `curl` commands, a Markdown report and raw JSON.

## Privacy

TenantProbe only reads public DNS and public Microsoft login metadata. Nothing is stored. DNS queries go from your browser to Cloudflare DNS-over-HTTPS; the two Microsoft endpoints are fetched by a small server proxy (`/api/probe`) because they do not allow cross-origin requests.

## Run locally

```sh
npm install
npm run dev
```

## Build & deploy

```sh
npm run build
```

The build targets edge runtimes (Cloudflare Workers by default). A standalone Vercel Edge function is also included in `api/scan.ts` with `vercel.json`.

## Tests

```sh
npm test
```

## Stack

TanStack Start, React, TypeScript, Tailwind CSS.

## License

MIT

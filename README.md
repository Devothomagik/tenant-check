# tenant-check

I built this to answer a question I kept asking by hand: how is this domain set up on Microsoft 365 / Entra ID, and is its email authentication any good? Type in a domain and it looks everything up and marks each check PASS, WARN or MISSING, with a suggested fix next to it.

It is read-only. It only uses public DNS and Microsoft's public login metadata, and it doesn't store anything. Please only point it at domains you own or are authorized to assess.

## What it checks

- Tenant info from the public OpenID discovery document (tenant ID, region, cloud, issuer)
- Whether the domain is managed or federated, via getuserrealm, plus the brand name and federation URL
- The initial onmicrosoft.com tenant and the DKIM selector1 / selector2 CNAMEs
- SPF, including a recursive count of DNS lookups against the limit of 10, and the DMARC policy
- MX records (and a guess at the mail gateway), Intune enrollment and registration, Autodiscover, MTA-STS and TLS-RPT

Each result also shows the equivalent dig / curl commands so you can double-check it yourself, and you can copy the whole thing as a Markdown report or raw JSON.

## How it works

DNS queries go straight from the browser to Cloudflare's DNS-over-HTTPS. The two Microsoft login endpoints don't allow cross-origin requests, so those go through a small server route, /api/probe.

## Running it

```sh
bun install
bun run dev
```

Tests are run with bun run test. The build (bun run build) targets Cloudflare Workers by default. There's also a Vercel edge function in api/scan.ts with a vercel.json if you'd rather deploy there.

It's built with TanStack Start, React, TypeScript and Tailwind.

## License

MIT

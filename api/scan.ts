// Vercel Serverless Function (Web standard signature). Mirrors src/routes/api/scan.ts for Vercel deployments.
import { DOMAIN_RE, probeMicrosoft } from "../src/lib/ms-probe";

export const config = { runtime: "edge" };

export default async function handler(request: Request): Promise<Response> {
  const domain = (new URL(request.url).searchParams.get("domain") ?? "").trim().toLowerCase();
  if (!DOMAIN_RE.test(domain)) return Response.json({ error: "invalid domain" }, { status: 400 });
  return Response.json(await probeMicrosoft(domain), { headers: { "cache-control": "no-store" } });
}

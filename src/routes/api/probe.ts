import { createFileRoute } from "@tanstack/react-router";
import { DOMAIN_RE, probeMicrosoft } from "@/lib/ms-probe";

export const Route = createFileRoute("/api/probe")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const domain = (new URL(request.url).searchParams.get("domain") ?? "").trim().toLowerCase();
        if (!DOMAIN_RE.test(domain))
          return Response.json({ error: "invalid domain" }, { status: 400 });
        try {
          return Response.json(await probeMicrosoft(domain), {
            headers: {
              "cache-control": "public, max-age=300",
              "x-content-type-options": "nosniff",
            },
          });
        } catch {
          return Response.json({ error: "upstream lookup failed" }, { status: 502 });
        }
      },
    },
  },
});

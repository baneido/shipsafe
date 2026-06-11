# shipsafe.dev landing page

Static, dependency-free landing page (single `index.html`).

## Local preview

```sh
python3 -m http.server -d site 8000
# → http://localhost:8000
```

## Deploy

The page deploys automatically to **GitHub Pages** via
`.github/workflows/pages.yml` on every push to `main`
(https://baneido.github.io/shipsafe/).

For the `shipsafe.dev` custom domain (manual, one-time):

1. Buy `shipsafe.dev` (Google Domains / Cloudflare / お名前.com).
2. Option A — GitHub Pages: add a `CNAME` file containing `shipsafe.dev`
   to this directory and configure the domain in repo Settings → Pages;
   point DNS `A`/`AAAA` at GitHub Pages or `CNAME` at
   `baneido.github.io`.
3. Option B — Vercel: `vercel --prod site/` and assign the domain in the
   Vercel dashboard.
4. `install.shipsafe.dev` should serve
   [`scripts/install.sh`](../scripts/install.sh) — e.g. a Cloudflare
   redirect rule to
   `https://raw.githubusercontent.com/baneido/shipsafe/main/scripts/install.sh`.

## Contact form

The form opens a pre-filled mail draft to `contact@baneido.com` (static
fallback). To switch to a hosted backend, create a Formspree form and put
its endpoint in the `<form action=...>`.

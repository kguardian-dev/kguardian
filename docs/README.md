# kguardian docs

Source for the kguardian documentation site, published to [docs.kguardian.dev](https://docs.kguardian.dev) via Mintlify on push to `main`.

Navigation and site configuration live in `docs.json`; pages are `.mdx` files in this directory.

Preview locally:

```bash
npm i -g mint
mint dev   # run from docs/, serves http://localhost:3000
```

If the preview misbehaves, run `mint update` to get the latest CLI. User-facing copy follows the repo [Style Guide](../STYLE.md).

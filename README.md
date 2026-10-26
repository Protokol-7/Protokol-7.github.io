# Protocol7.github.io

Source for Protocol7's cybersecurity research site, built with Jekyll and hosted on GitHub Pages.

## One-time GitHub setup

1. **Create the org.** On github.com, go to *Settings → Organizations → New organization*, name it `Protocol7`. Pick the free plan.
2. **Create this repo under the org**, named exactly `Protocol7.github.io` (that exact name is what makes GitHub Pages serve it at `https://protocol7.github.io`, with no project path suffix).
3. **Add the other two as owners.** *Org → People → Invite member*, set role to **Owner** for all three of you.
4. **Push this folder** as the initial commit (see commands below).
5. **Enable Pages.** *Repo → Settings → Pages → Build and deployment → Source: Deploy from a branch → Branch: `main` / `(root)`*. GitHub Pages builds Jekyll automatically — no CI config needed.
6. Replace the placeholder handles in [`team.md`](team.md) and [`.github/CODEOWNERS`](.github/CODEOWNERS) with your real GitHub usernames.

```bash
git init
git add .
git commit -m "Initial site scaffold"
git branch -M main
git remote add origin https://github.com/Protocol7/Protocol7.github.io.git
git push -u origin main
```

## Writing a new post

Copy a file in [`_posts/`](_posts/) to `_posts/YYYY-MM-DD-short-title.md` and fill in the front matter:

```yaml
---
title: "Challenge name or topic"
date: 2026-01-01 00:00:00 +0000
categories: [ctf]      # or [research], [tooling], etc.
tags: [reversing, pwn] # whatever fits
---
```

Write the body in Markdown below the front matter. Code blocks use triple backticks with a language hint for syntax highlighting (e.g. ` ```python `).

## Running locally

Requires Ruby + Bundler.

```bash
bundle install
bundle exec jekyll serve
```

Then open `http://localhost:4000`.

## Notes

- `about.md` and `team.md` are top-level pages; add more by creating a `.md` file at the repo root with `layout: page` front matter.
- Any research involving third-party software/services should follow the disclosure note in [`about.md`](about.md) before publishing.
- Keep in-progress notes, raw CTF artifacts, and anything not meant to be public out of this repo — it's public once Pages is enabled on the free org plan.

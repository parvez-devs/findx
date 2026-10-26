# FindX — Website Structure Analyzer

Flask website analyzer built from the supplied project draft. Enter a publicly accessible HTTP(S) URL to generate a point-by-point report of the returned HTML, including headings, paragraphs, links, forms, buttons, and scripts.

## Deploy on Render
- Web Service / Python 3.12 / Free plan.
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 2 --timeout 40 app:app`
- Database and secrets: none required.

## Run locally
```sh
pip install -r requirements.txt
python app.py
```

## Safety / limitations
- Only public HTTP(S) pages on ports 80/443, limited redirects and 2 MB response body.
- Private IPs are blocked and DNS results pinned to the connected IP to mitigate SSRF.
- This extracts server-returned HTML only; it does not execute browser JavaScript or inspect private server-side code.
- Reports are stored on Render's ephemeral filesystem. Download them immediately; redeploys and restarts can remove them.

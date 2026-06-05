# CyberShield

AI-powered cybersecurity report generator for homeowners and small business owners.

Part of [HoustonSecureIT.com](https://houstonsecureit.com).

## Stack
- Frontend: Single `index.html` at project root
- Backend: Flask Python function at `api/index.py`
- Hosting: Vercel
- Domain: `cybershield.houstonsecureit.com`

## Local development

```bash
pip install -r requirements.txt
python api/index.py
# Visit http://localhost:5000
```

## Endpoints
- `GET /` — homepage
- `POST /api/report` — generate a cybersecurity report
- `GET /health` — health check

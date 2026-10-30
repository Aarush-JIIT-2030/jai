# Vercel & Supabase Deployment Architecture

## Frontend & Serverless Deployment (Vercel)

- **Framework:** React 19 + TypeScript + Vite.
- **Vercel Functions:** Python runtime serving `/api/` endpoints.
- **Build Command:** `npm run build`
- **Output Directory:** `dist`
- **Routing:** Handled via `vercel.json`:
  - `/api/health` -> `api/health.py`
  - `/api/models/status` -> `api/models/status.py`
  - `/api/analyze/batch` -> `api/analyze/batch.py`
  - `/api/analyze` -> `api/analyze/index.py`
  - `/(.*)` -> `/dist/$1`

## Database & Session Persistence (Supabase)

- **Auth:** Supabase Email & Password authentication.
- **Guest Mode:** Offline local session fallback for demonstration without cloud credentials.
- **Row-Level Security (RLS):**
  - All run telemetry and audit rows are tied to `auth.uid() = user_id`.
  - Service-role key is never bundled in frontend code.

# Valley Town Online

Render-ready persistent backend wrapper for the Valley Town extraction shooter.

## What is included

- `public/index.html` / `public/template2.html`: the updated game client with:
  - login screen
  - main menu overlay
  - profile tab
  - backend profile sync when logged in
  - offline guest fallback
- `server.js`: Express + Socket.IO backend.
- Persistent profile API:
  - `POST /api/register`
  - `POST /api/login`
  - `GET /api/profile`
  - `PUT /api/profile`
  - `GET /api/health`
- Storage:
  - Render/Postgres when `DATABASE_URL` exists
  - local JSON fallback at `data/profiles.json` for development
- `render.yaml`: Render web service + Postgres blueprint.

## Local run

```bash
npm install
npm start
```

Then open:

```text
http://127.0.0.1:4173/
```

## Render deployment

Push this folder to GitHub and create a Render Blueprint from `render.yaml`.
Render will provision:

- web service: `valley-town-online`
- database: `valley-town-online-db`

The app binds to `process.env.PORT` and `0.0.0.0` when running on Render.

## Notes

This is the first persistence/auth foundation. Socket.IO is included and wired with a placeholder connection event so party/matchmaking can be added next without changing transports.

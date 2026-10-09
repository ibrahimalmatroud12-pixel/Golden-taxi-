# Golden Taxi Chiron

## Deploy Render
- Create PostgreSQL and Web Service from this repository.
- Root directory `backend`; build `npm install`; start `npm start`.
- Add DATABASE_URL (Render internal URL), JWT_SECRET, ENCRYPTION_KEY, ADMIN_PASSWORD_HASH.

## Chiron
Add TEST credentials from dashboard, run `hello`, then create 5 distinct test trips. Send vertrek then aankomst for each one. Do not send production traffic until acceptance succeeds. Secrets are encrypted at rest in this starter but production should use a dedicated credentials vault and user/role controls.

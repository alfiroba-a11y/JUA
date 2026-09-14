# JUA deployment guide

JUA is a Node 20, Express and PostgreSQL application ready for a Render Web Service. It creates and uses its own `jua` PostgreSQL schema, so it does not collide with an existing public `users` table in a shared database.

## Deploy on Render

1. Upload this `jua` folder to a private GitHub repository.
2. Create a Render PostgreSQL database and copy its **Internal Database URL**.
3. Create a Render Web Service from the repository. Set Build Command to `npm install` and Start Command to `npm start`.
4. Add the environment variables below, then deploy. The database schema and starter question set initialise on boot.
5. Point your purchased domain at the Render service, then enable Render-managed TLS.

## Required environment variables

```text
DATABASE_URL=Render internal PostgreSQL URL
JWT_SECRET=a long randomly generated secret
MOBILE_MONEY_BASE_URL=payment service API base URL
MOBILE_MONEY_API_KEY=merchant API key
MOBILE_MONEY_ACCOUNT_ID=merchant account ID
MOBILE_MONEY_WEBHOOK_SECRET=webhook signing secret
ADMIN_PHONE=your Kenyan mobile number in 2547XXXXXXXX format
```

Keep every value in Render’s secret environment variables; do not commit a `.env` file. `MOBILE_MONEY_SECURITY_CREDENTIAL` is reserved for a later provider-approved automated payout integration and is not required for withdrawal requests in this release.

## Payment webhook

After the Render service has a public HTTPS domain, configure this callback URL in the payment portal:

```text
https://your-domain.com/api/payments/webhook
```

Save the portal's webhook signing secret as `MOBILE_MONEY_WEBHOOK_SECRET` in Render. The endpoint verifies the signature over the exact raw request body, matches the provider checkout reference, amount and mobile number to a pending JUA deposit, and credits the wallet in one database transaction. Duplicate callbacks do not create a second credit.

## What is enforced in the app

- Account registration and sign-in are required before wallet or game access.
- Minimum deposit is KES 200; minimum stake is KES 50.
- The mobile payment prompt goes only to the number the player enters.
- A deposit is credited only after the server confirms it with the payment service.
- Every profile receives unseen questions only; `seen_questions` prevents repeats.
- All game scoring is performed on the server.
- Withdrawal requests capture an amount and Kenyan mobile number and remain traceable in the database.

## Question bank

The included editorial starter pack is intentionally small and reviewable. Add more questions directly to the `questions` table or an admin workflow; the database has no artificial question limit. All paid-game questions should be fact checked and reviewed before publication.

## Launch controls

Before enabling paid entry, obtain Kenyan legal advice and approvals, complete age/KYC and responsible-play controls, configure a secure password reset/phone verification service, rate-limit authentication, implement payment callback verification appropriate to your merchant account, and commission an independent security review.

## Admin dashboard

Set `ADMIN_PHONE` in Render before creating the administrator account. Register with that exact number, then sign in and open `/admin` on your domain. The dashboard shows registered members, wallet totals, withdrawal requests and the question bank, and lets the administrator add, pause or reactivate questions. Do not share the administrator account credentials.

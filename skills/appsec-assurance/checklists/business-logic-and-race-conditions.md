# Business logic and race conditions

Scope: flaws in how the application implements its own rules rather than in
generic sinks: state machines and workflow ordering, multi-step process bypass,
concurrency (TOCTOU, double spend, limit overrun), idempotency, numeric edge
cases, client-trusted prices and discounts, time-based logic and abuse of
sensitive business flows. Scanners rarely find these; derive abuse cases from
the threat model and the product's rules.

**Applies when:** payments, wallets, credits, carts, coupons, quotas, voting,
inventory, bookings, invitations, approvals, trials, referral programs,
rewards, KYC or any multi-step flow exists.

**Standards:** OWASP A04:2021 Insecure Design, A01:2021; API6:2023 Unrestricted
Access to Sensitive Business Flows, API4:2023; ASVS V2 Validation and Business
Logic; CWE-840, CWE-841, CWE-362, CWE-367, CWE-366, CWE-820, CWE-190, CWE-191,
CWE-681, CWE-1284, CWE-20, CWE-602, CWE-799.

## Method
For each sensitive flow write the intended rules in one sentence each (who,
when, how many times, in what order, within what limits). Then ask for each:
can it be done twice, out of order, concurrently, with a negative/huge/fractional
value, by another user, after expiry, or by skipping a step?

## Items

- **BIZ-01 — Explicit state machine with server-side transition checks** (high)
  - Verify: order/payment/approval status changes go through a single transition function that checks current state (`if order.status != 'pending': reject`); grep direct `status =` assignments in controllers; libraries (AASM, django-fsm, XState on server, Spring Statemachine).
  - Fail: `PATCH /orders/1 {"status":"paid"}` accepted; refund allowed on unpaid orders.
- **BIZ-02 — Workflow step enforcement** (high)
  - Verify: multi-step flows (checkout, onboarding, KYC, MFA enrollment, password reset) track completion server-side; final step verifies all prior steps for *this* session/object.
  - Fail: calling step 3 directly skips payment or verification.
- **BIZ-03 — Check-then-act races (TOCTOU)** (high)
  - Verify: balance/quota/inventory/coupon checks followed by a separate write without a lock or atomic condition. Look for `SELECT ... ; if ok: UPDATE` patterns, ORM `get()` then `save()`, Redis `GET` then `SET`. Correct: `UPDATE ... SET bal = bal - :x WHERE id=:id AND bal >= :x` with affected-rows check, `SELECT ... FOR UPDATE` inside a transaction, optimistic locking (`version` column), unique constraints, Redis `INCR`/Lua, serializable isolation where needed.
  - Fail: N parallel redemptions of a single-use coupon or N withdrawals exceeding balance.
- **BIZ-04 — Double spend and duplicate submission** (high)
  - Verify: payment capture, transfers, credit grants, reward claims, gift card redemption are idempotent and single-use, enforced by DB constraints, not only app checks.
  - Fail: double-click or replay creates two charges/credits.
- **BIZ-05 — Idempotency keys** (medium–high)
  - Verify: mutating payment/order APIs accept and enforce `Idempotency-Key` scoped per user/endpoint, stored with request hash, returning the original response on retry; mismatched payload with same key rejected; keys expire.
  - Fail: key accepted but not bound to user (cross-user response leak) or not stored atomically.
- **BIZ-06 — Price, total and discount computed server-side** (critical)
  - Verify: price, currency, tax, shipping, discount and total recomputed from server catalog; client-sent `price`, `amount`, `total`, `discount` ignored; payment provider amount matches server order total at confirmation (webhook reconciles amount and currency).
  - Fail: hidden form field `price=1`; trusting client total; webhook marks order paid without comparing amount.
- **BIZ-07 — Coupon and promotion abuse** (medium)
  - Verify: per-user/per-order usage limits, stacking rules, expiry, minimum order re-checked after cart changes, codes not enumerable (rate limits, sufficient entropy), referral self-referral prevention.
  - Fail: apply coupon then remove qualifying items; unlimited redemptions; sequential codes.
- **BIZ-08 — Numeric edge cases** (high)
  - Verify: negative quantities/amounts, zero, fractional quantities, very large values (overflow in int32/int64, JS `Number` > 2^53), floating-point money (`float`/`double` for currency), rounding direction, currency precision differences (JPY 0 decimals), `NaN`/`Infinity` from parsing. Use integer minor units or decimal types; validate ranges.
  - Fail: `quantity=-1` refunds money; transfer of `-100` reverses direction; `0.1+0.2` rounding exploited at scale.
- **BIZ-09 — Limits and quotas enforcement** (medium)
  - Verify: plan limits (seats, projects, API calls, storage) enforced at write time server-side, including via bulk/import endpoints and concurrent requests.
  - Fail: free tier exceeds limits via parallel requests or import API.
- **BIZ-10 — Time-based logic** (medium)
  - Verify: server clock used (not client timestamps); time zones/DST handled for expiry and scheduling; trial resets prevented (new account, email aliasing `user+1@`), token/offer expiry checked at use not only at issue; deadlines enforced at commit time.
  - Fail: client-supplied `timestamp` determines eligibility; trials renewable by changing email suffix.
- **BIZ-11 — Sensitive flow automation (API6)** (medium)
  - Verify: flows valuable to bots (sign-up, ticket/inventory purchase, posting, voting, SMS/email send, password reset, gift card check) have rate limits, device/behavioral signals or CAPTCHA, and anomaly monitoring.
  - Fail: scalpable inventory, SMS pumping/toll fraud via unprotected OTP send.
- **BIZ-12 — Ownership and transfer rules** (high)
  - Verify: transferring objects (gift cards, credits, ownership of org/repo) checks both sides; can't transfer to self to trigger bonuses; reversals handled.
- **BIZ-13 — Cancellation, refund and rollback paths** (high)
  - Verify: refunds limited to captured amount minus prior refunds; cancel after fulfillment blocked or reconciled; partial failures in distributed transactions compensate correctly (sagas/outbox) and don't leave granted value without payment.
  - Fail: refund + chargeback double recovery; cancel race with fulfillment.
- **BIZ-14 — Trust in third-party/state callbacks** (high)
  - Verify: payment/KYC/shipping webhooks authenticated (SSRF-08), idempotent, ordered (late "failed" after "succeeded"), and matched to the right order/user.
  - Fail: forged or replayed webhook marks orders paid.
- **BIZ-15 — Invitations and role grants** (medium)
  - Verify: invite tokens single-use, bound to the invited email, expire; accepting an invite cannot elevate role beyond what was issued; invite to org A not usable in org B.
- **BIZ-16 — Unique constraints backing business rules** (medium)
  - Verify: "one per user" rules have DB unique indexes (votes, reviews, redemptions, usernames case-insensitive/Unicode-normalized).
  - Fail: app-level uniqueness check only (race); `Admin` vs `admin` vs homoglyph usernames.

## Common false positives
- Races on non-valuable, idempotent operations (e.g. updating a display name).
- Client-side price shown for UX while server recomputes (verify the server path, then pass).
- Negative values rejected by DB `CHECK` constraints — read migrations before reporting.

## Safe validation ideas
- Prefer static proof: show the non-atomic read → write sequence with file:line and the absent lock/constraint.
- Unit/integration test against a local DB: run two concurrent calls (threads/`Promise.all`, 2–5 parallel requests, not floods) redeeming a seeded single-use coupon `APPSEC-CANARY-<rand>`, and assert only one succeeds.
- Numeric: on a local instance with a test account, submit `quantity=-1` / `amount=0.001` and check rejection. Use test-mode payment providers only; never real payments.

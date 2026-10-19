import { Router } from 'express';

const billingRouter = Router();

function requireJwtAuth(req: any, res: any, next: any) {
  next();
}

// @stelfid-keep: annual-tax-reconciliation-webhook
billingRouter.post('/annual-tax-webhook', requireJwtAuth, (req, res) => {
  res.json({ ok: true, note: 'Executed once per fiscal year' });
});

// @stelfid-deprecated: sunset=2026-12-31
billingRouter.get('/invoices-legacy-xml', requireJwtAuth, (req, res) => {
  res.json({ deprecated: true, format: 'xml' });
});

export default billingRouter;

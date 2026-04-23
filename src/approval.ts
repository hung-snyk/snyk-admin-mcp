const TTL_MS = 10 * 60 * 1000; // 10 minutes

interface PendingApproval {
  plan: unknown;
  createdAt: number;
}

const store = new Map<string, PendingApproval>();

function prune(): void {
  const now = Date.now();
  for (const [id, p] of store.entries()) {
    if (now - p.createdAt > TTL_MS) store.delete(id);
  }
}

export function createApproval(plan: unknown): string {
  prune();
  const id = `snyk-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  store.set(id, { plan, createdAt: Date.now() });
  return id;
}

export function consumeApproval(approvalToken: string): unknown {
  prune();
  const p = store.get(approvalToken);
  if (!p) return null;
  store.delete(approvalToken);
  if (Date.now() - p.createdAt > TTL_MS) return null;
  return p.plan;
}

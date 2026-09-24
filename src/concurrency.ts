/**
 * A minimal bounded-concurrency map: runs `fn` over every item in `items`,
 * never running more than `limit` invocations at once. Used everywhere we
 * touch the network (DNS lookups, port probes, TLS handshakes) so a scan
 * can never fan out into an unbounded flood of concurrent connections.
 */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  if (limit <= 0) throw new Error("concurrency limit must be positive");
  const results: R[] = new Array(items.length);
  let nextIndex = 0;

  async function worker(): Promise<void> {
    while (true) {
      const current = nextIndex++;
      if (current >= items.length) return;
      results[current] = await fn(items[current], current);
    }
  }

  const workers = Array.from({ length: Math.min(limit, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

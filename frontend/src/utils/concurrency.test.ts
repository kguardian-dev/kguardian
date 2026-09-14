import { describe, expect, test } from 'vitest';
import { withConcurrencyLimit } from './concurrency';

const deferred = () => {
  let resolve!: (v: string) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<string>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
};

const tick = async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); };

describe('withConcurrencyLimit', () => {
  test('resolves results in task order, not completion order', async () => {
    const out = await withConcurrencyLimit(
      [
        () => new Promise<string>((r) => setTimeout(() => r('slow'), 10)),
        () => Promise.resolve('fast'),
      ],
      2,
    );
    expect(out).toEqual(['slow', 'fast']);
  });

  test('runs at most `limit` at a time', async () => {
    let running = 0;
    let peak = 0;
    const task = () => async () => {
      running++;
      peak = Math.max(peak, running);
      await Promise.resolve();
      running--;
      return 'ok';
    };
    await withConcurrencyLimit(Array.from({ length: 12 }, task), 3);
    expect(peak).toBeLessThanOrEqual(3);
  });

  // Fail-fast, as the inline original was: against a shedding broker a large
  // namespace must cost about one wave of requests, not every task queued
  // behind it — and the caller is usually holding a `loading` flag.
  test('stops starting tasks once one has failed, and rejects with that failure', async () => {
    const ran: number[] = [];
    const tasks = [
      () => { ran.push(1); return Promise.reject(new Error('boom')); },
      () => { ran.push(2); return Promise.resolve('b'); },
      () => { ran.push(3); return Promise.resolve('c'); },
      () => { ran.push(4); return Promise.resolve('d'); },
    ];
    await expect(withConcurrencyLimit(tasks, 2)).rejects.toThrow('boom');
    expect(ran).toEqual([1, 2]); // the wave in flight when it failed, nothing after
  });

  test('a failure surfaces even when it is the last task', async () => {
    await expect(withConcurrencyLimit([() => Promise.resolve('a'), () => Promise.reject(new Error('late'))], 4))
      .rejects.toThrow('late');
  });

  // A rejected task must still leave the in-flight set (the `finally`), or the
  // limiter never drops below `limit` again and the run hangs instead of
  // rejecting.
  test('a rejecting task settles the run rather than wedging it', async () => {
    const gate = deferred();
    const run = withConcurrencyLimit([() => Promise.reject(new Error('boom')), () => gate.promise], 1);
    await tick();
    gate.resolve('never started');
    await expect(run).rejects.toThrow('boom');
  });

  test('a task that throws synchronously is caught like any rejection', async () => {
    const tasks = [
      () => { throw new Error('sync boom'); },
      () => Promise.resolve('b'),
    ];
    await expect(withConcurrencyLimit(tasks, 2)).rejects.toThrow('sync boom');
  });

  test('an empty task list resolves to an empty array', async () => {
    expect(await withConcurrencyLimit([], 4)).toEqual([]);
  });
});

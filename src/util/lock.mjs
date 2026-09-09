// A per-key promise-chain mutex. Termix file-manager and docker sessions are
// stateful (working directory, sudo password, open exec channels), so two tool
// calls against one host must not interleave. Calls against different hosts run
// concurrently because they use different keys.
export function createKeyedMutex() {
  const tails = new Map();

  return function runExclusive(key, task) {
    const previous = tails.get(key) ?? Promise.resolve();
    // The next caller waits for this task regardless of how it settles, so one
    // rejection does not wedge the chain.
    const run = previous.then(() => task(), () => task());
    const tail = run.catch(() => {});
    tails.set(key, tail);
    // Release the map entry once this is the last link, so idle keys do not leak.
    tail.finally(() => {
      if (tails.get(key) === tail) tails.delete(key);
    });
    return run;
  };
}

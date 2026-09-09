// Termix answers some mutating endpoints with HTTP 200 and a body saying the
// operation failed -- `{ success: false, output: "kill: (4194304) - No such
// process" }`. Passed through untouched that is a successful tool result, and
// the caller has to notice a `false` buried in the payload. It is the same
// failure direction as run_command's exit code always being 0: wrong, and wrong
// towards "it worked".
export function assertUpstreamOk(result, action) {
  if (result && typeof result === 'object' && result.success === false) {
    const detail = result.output ?? result.error ?? result.message ?? '';
    const text = String(detail).trim();
    throw new Error(text ? `${action} failed: ${text}` : `${action} failed (Termix reported success: false)`);
  }
  return result;
}

// Some endpoints go further and report success for a target that never existed
// -- dismissing an unknown alert id, disconnecting an unknown tunnel. Termix
// does not confirm the target, so neither can we; say so in the result rather
// than let a model report "done" for something that never happened.
export function withUnconfirmedTarget(result, what) {
  const body = (result && typeof result === 'object' && !Array.isArray(result)) ? result : { result };
  return {
    ...body,
    unconfirmed: `Termix acknowledges this request without checking that ${what} exists, so this `
      + 'response is not evidence the target was found. Verify with the corresponding list tool.',
  };
}

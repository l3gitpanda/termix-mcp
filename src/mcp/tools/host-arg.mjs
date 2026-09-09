import { z } from 'zod';

// One definition of the host argument, because this describe() is the only
// thing steering the model toward passing a NAME instead of an id.
//
// A Termix host id is an internal record id. It has no relation to the guest's
// PVE VMID, so a numeric argument reads as an unrecognisable number wherever
// the call is displayed -- the client's tool-call view, the audit JSONL, a
// refusal message -- and nobody can tell which machine was touched without
// looking it up. resolve() accepts a name, an IP, or an id equally, so the name
// costs nothing and carries meaning.
//
// Caveat worth knowing: resolve() treats an all-digits string as an id, so a
// host literally NAMED "112" cannot be addressed by that name.
export const HOST_ARG_DESCRIPTION =
  'Host name as shown by list_hosts, e.g. "app-main". A numeric Termix record id also works, '
  + 'but it is an internal id unrelated to the guest or VM number and is opaque in logs and '
  + 'tool-call displays -- prefer the name.';

export const hostArg = z.union([z.number(), z.string()]).describe(HOST_ARG_DESCRIPTION);

// For tools that need to add a condition without losing the guidance above.
export const hostArgWith = (extra) =>
  z.union([z.number(), z.string()]).describe(`${HOST_ARG_DESCRIPTION} ${extra}`);

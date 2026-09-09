import { randomUUID } from 'node:crypto';

// Session ids are prefixed by pool so the two maps never collide and a stray id
// in a Termix log is self-describing.
export function fileSessionId(hostId) {
  return `mcp-fm-${hostId}-${randomUUID()}`;
}

export function dockerSessionId(hostId) {
  return `mcp-dk-${hostId}-${randomUUID()}`;
}

export function auditId() {
  return randomUUID();
}

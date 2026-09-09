import { createRequire } from 'node:module';

// /healthz and the audit log report this, so a deployed instance can always be
// traced to the exact package version it was built from.
const require = createRequire(import.meta.url);
export const { version } = require('../package.json');

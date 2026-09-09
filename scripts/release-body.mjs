import fs from 'node:fs';
import { extractRelease, buildReleaseBody } from '../src/changelog.mjs';

// Prints the release body for a version: its changelog section, followed by
// how to pull the image. Written to stdout so the workflow can redirect it
// without a temp-file dance. Shares buildReleaseBody with the backfill so a
// freshly cut release and a backfilled one are indistinguishable.
const [tag, image, short] = process.argv.slice(2);
const version = String(tag).replace(/^v/, '');
const notes = extractRelease(fs.readFileSync('CHANGELOG.md', 'utf8'), version);

if (!notes) {
  console.error(`CHANGELOG.md has no "## ${version}" section.`);
  process.exit(1);
}

process.stdout.write(buildReleaseBody({ notes, image, tag, short }));

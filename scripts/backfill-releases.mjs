import fs from 'node:fs';
import { extractRelease, buildReleaseBody } from '../src/changelog.mjs';

// Give every existing release the changelog section it was published without.
//
// The release job already writes the changelog section into the body of every
// release it cuts, so this is the repair path: releases published before an
// entry existed (or whose entry was edited afterwards) get rewritten from
// CHANGELOG.md, which is the record that survives.
//
// DRY RUN BY DEFAULT. It rewrites published, externally-visible text, so it
// prints what it would change and does nothing unless APPLY=1 is set.

const { SERVER_URL, REPOSITORY, TOKEN, IMAGE, APPLY } = process.env;
const apply = APPLY === '1';

if (!SERVER_URL || !REPOSITORY || !TOKEN) {
  console.error('SERVER_URL, REPOSITORY and TOKEN are required');
  process.exit(1);
}

const api = `${SERVER_URL}/api/v1/repos/${REPOSITORY}`;
const headers = { Authorization: `token ${TOKEN}`, 'Content-Type': 'application/json' };
const changelog = fs.readFileSync('CHANGELOG.md', 'utf8');

async function main() {
  const response = await fetch(`${api}/releases?limit=100`, { headers });
  if (!response.ok) {
    console.error(`could not list releases: HTTP ${response.status}`);
    console.error('The token needs read access to this repository.');
    process.exit(1);
  }
  const releases = await response.json();
  console.log(`${releases.length} releases found; apply=${apply}\n`);

  let updated = 0;
  let skippedNoNotes = 0;
  let skippedSame = 0;

  for (const release of releases) {
    const tag = release.tag_name;
    const notes = extractRelease(changelog, tag);
    if (!notes) {
      // Not a failure: a tag may predate the changelog deliberately, and
      // inventing notes for it would be worse than leaving it alone.
      console.log(`skip   ${tag.padEnd(10)} no changelog section`);
      skippedNoNotes += 1;
      continue;
    }

    const body = buildReleaseBody({
      notes,
      image: IMAGE ?? 'registry.example.com/OWNER/termix-mcp',
      tag,
      // The commit a release was cut from is not reliably recoverable from the
      // API, and a wrong sha is worse than none, so the immutable-tag line is
      // simply omitted on backfilled bodies.
      short: undefined,
    });

    if ((release.body ?? '').trim() === body.trim()) {
      console.log(`same   ${tag.padEnd(10)} already correct`);
      skippedSame += 1;
      continue;
    }

    if (!apply) {
      console.log(`WOULD  ${tag.padEnd(10)} rewrite ${(release.body ?? '').length} -> ${body.length} chars`);
      updated += 1;
      continue;
    }

    const patch = await fetch(`${api}/releases/${release.id}`, {
      method: 'PATCH',
      headers,
      // Only the body. The tag, target commit, name and attached assets are left
      // exactly as they are -- this is an annotation pass, not a re-release.
      body: JSON.stringify({ body }),
    });
    if (!patch.ok) {
      console.error(`FAIL   ${tag.padEnd(10)} HTTP ${patch.status}`);
      process.exitCode = 1;
      continue;
    }
    console.log(`ok     ${tag.padEnd(10)} updated`);
    updated += 1;
  }

  console.log(`\n${apply ? 'updated' : 'would update'}: ${updated}, unchanged: ${skippedSame}, no notes: ${skippedNoNotes}`);
  if (!apply && updated > 0) console.log('Re-run with APPLY=1 to write these.');
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});

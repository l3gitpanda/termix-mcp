// Pull one version's section out of CHANGELOG.md.
//
// Driver-free and string-only so the release job's body can be checked without
// running the release job -- the alternative is discovering a broken heading
// level only when a tag is already pushed and the release already wrong.

// Headings are `## <version>`, optionally followed by anything (a date, a name).
function headingVersion(line) {
  const match = /^##\s+v?(\d+\.\d+\.\d+)\b/.exec(line);
  return match ? match[1] : null;
}

export function listVersions(markdown) {
  return String(markdown ?? '')
    .split('\n')
    .map(headingVersion)
    .filter(Boolean);
}

export function extractRelease(markdown, version) {
  const wanted = String(version ?? '').replace(/^v/, '');
  if (!wanted) return null;

  const lines = String(markdown ?? '').split('\n');
  let start = -1;
  for (let i = 0; i < lines.length; i += 1) {
    if (headingVersion(lines[i]) === wanted) { start = i + 1; break; }
  }
  if (start === -1) return null;

  const body = [];
  for (let i = start; i < lines.length; i += 1) {
    if (headingVersion(lines[i])) break;
    body.push(lines[i]);
  }

  const text = body.join('\n').trim();
  return text || null;
}

// The full release body: the notes, then how to get the thing. Shared by the
// release job and the backfill so an old release reads identically to a new one
// -- the point of backfilling is that they become indistinguishable.
//
// `short` is optional because a backfill knows the tag but not necessarily the
// commit it was cut from, and inventing one would be worse than omitting it.
export function buildReleaseBody({ notes, image, tag, short }) {
  if (!notes) return null;
  const lines = ['## Pull the image', '', `    docker pull ${image}:${tag}`];
  if (short) {
    lines.push('', `Also published as \`:latest\` and as the immutable \`:sha-${short}\`.`);
  } else {
    lines.push('', 'Also published as `:latest`.');
  }
  return `${notes}\n\n${lines.join('\n')}\n`;
}

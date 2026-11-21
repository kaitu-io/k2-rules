#!/usr/bin/env bash
# Publish the given artifact files as the ONLY commit on the release branch.
#
#   scripts/sync-release-branch.sh <file>...
#
# The release branch exists so jsdelivr can serve the artifacts from
# @release. Appending a commit per night kept every past tarball reachable
# (~5 MB/night; the repo reached 1 GB after 231 nightlies), so each run
# replaces the branch with a single parentless commit instead. jsdelivr
# resolves @release to the branch head at fetch time, so a rewritten head is
# served exactly like an appended one.
#
# Built with plumbing in a throwaway index: the working tree and the checked
# out branch are never touched, so leftovers from earlier build steps cannot
# leak into the published tree.
#
# Env: RELEASE_REMOTE (default origin), RELEASE_BRANCH (default release).
set -euo pipefail

remote="${RELEASE_REMOTE:-origin}"
branch="${RELEASE_BRANCH:-release}"

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <file>..." >&2
  exit 2
fi

GIT_INDEX_FILE="$(mktemp -u)"
export GIT_INDEX_FILE
trap 'rm -f "$GIT_INDEX_FILE"' EXIT

for f in "$@"; do
  # An empty or missing artifact must never replace a good one on the CDN.
  if [ ! -s "$f" ]; then
    echo "FAIL: artifact missing or empty: $f" >&2
    exit 1
  fi
  blob="$(git hash-object -w -- "$f")"
  git update-index --add --cacheinfo "100644,${blob},$(basename -- "$f")"
done
tree="$(git write-tree)"

# Current head, if the branch exists. An empty $old makes the lease below
# require that the branch does NOT exist, so a failed fetch cannot turn into
# a blind overwrite.
old=""
if git fetch --quiet --depth=1 "$remote" "refs/heads/${branch}"; then
  old="$(git rev-parse FETCH_HEAD)"
  if [ "$(git rev-parse "FETCH_HEAD^{tree}")" = "$tree" ]; then
    echo "no changes to ${branch} branch"
    exit 0
  fi
fi

commit="$(git commit-tree "$tree" -m "nightly: $(date -u +%Y-%m-%dT%H:%MZ)")"
git push --force-with-lease="refs/heads/${branch}:${old}" "$remote" "${commit}:refs/heads/${branch}"
echo "${branch} -> ${commit} (single commit, replaced ${old:-nothing})"

#!/usr/bin/env bash
# Commit ads/ledger.tsv to master if the build changed it.
#
# The ledger is the quarantine's memory: the date each upstream ads entry was
# first seen (ads_gate.go). The build rewrites it in the working tree; this
# persists it. A run that cannot persist it fails, and that is safe — an
# unrecorded entry is simply "first seen" again tomorrow, so a lost write can
# only lengthen a quarantine, never shorten one.
#
# Env: LEDGER_REMOTE (default origin), LEDGER_BRANCH (default master).
set -euo pipefail

remote="${LEDGER_REMOTE:-origin}"
branch="${LEDGER_BRANCH:-master}"
ledger="ads/ledger.tsv"

if git diff --quiet -- "$ledger"; then
  echo "ads ledger unchanged"
  exit 0
fi

git --no-pager diff --stat -- "$ledger"
git commit --quiet --only -m "chore(ads): ledger $(date -u +%Y-%m-%d)" -- "$ledger"

# master may have moved since checkout (a developer push). The ledger is one
# machine-written file nobody else edits, so replaying this single commit on
# top of the new head cannot conflict with real work.
for attempt in 1 2 3; do
  if git push --quiet "$remote" "HEAD:refs/heads/${branch}"; then
    echo "ads ledger committed to ${branch}"
    exit 0
  fi
  echo "push rejected (attempt ${attempt}), rebasing onto ${remote}/${branch}"
  git fetch --quiet "$remote" "refs/heads/${branch}"
  git rebase --quiet FETCH_HEAD
done
echo "FAIL: could not push the ads ledger" >&2
exit 1

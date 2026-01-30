#!/usr/bin/python3

import argparse
import dataclasses
import difflib
import os
import re
import subprocess
import sys
import urllib

import requests

DEFAULT_FROM = 'HEAD'
DEFAULT_BUGZILLA_URL = 'https://bugzilla.suse.com'

DEFAULT_BUG_TAGS = ['bsc', 'boo', 'bnc']

MISSING_BUG_STRINGS = (
    'Missing Bug ID',
    'You must enter a valid bug number!',
)
PRIVATE_BUG_STRINGS = (
    'Bug Access Denied',
    'You are not authorized to access bug',
    'To see this bug, you must first',
)

# Similarity threshold for bug IDs
SIMILARITY_THRESHOLD = 0.8


@dataclasses.dataclass
class Commit:
    """A class to hold some fields of a git commit"""

    commit_id: str
    message: str
    diff: str

    def __str__(self) -> str:
        return self.commit_id + '\n' + self.message + '\n' + self.diff

    def lines_added(self) -> list[str]:
        """Return a list of '+' lines in this commit."""
        if self.diff:
            return '\n'.join(ln for ln in self.diff.splitlines() if (ln.startswith('+') and not ln.startswith('+++')))
        else:
            return []

    def lines_removed(self) -> list[str]:
        """Return a list of '-' lines in this commit."""
        if self.diff:
            return '\n'.join(ln for ln in self.diff.splitlines() if (ln.startswith('-') and not ln.startswith('---')))
        else:
            return []


def validate_bug_tags(tags: list[str]) -> list[str]:
    """Validate a list of bug tags.

    Valid bug tags are short (len < 16) alphanumeric words.
    """
    r = []
    for t in tags:
        if t.isalnum() and len(t) < 16:
            r.append(t)
        else:
            print(f'Skipping invalid bug tag "{t}"', file=sys.stderr)
    return r


def validate_url(s: str) -> str:
    u = urllib.parse.urlparse(s)
    # Recognize naked URLs as netlocs (e.g. bugzilla.suse.com)
    if not u.netloc:
        u.netloc = u.path
    return u._replace(path='', params='', query='', fragment='').geturl()


def bugnum(bugid: str) -> str:
    """Convert a bug ID (bsc#123456) to a bug number (123456)."""
    if '#' in bugid:
        return bugid.split(sep='#', maxsplit=1)[1]
    if bugid.isdigit():
        return bugid
    raise ValueError(f'Unknown bug ID: {bugid}')


def extract_commit_data(range_revs: list[str], bug_regex: re.Pattern) -> (dict, dict):
    """Extract data from Git commits passed as a list of ids.

    Return a tuple (commits, bugs) where:
      - commits is a dict[id, Commit]
      - bugs is a dict[bugid, list]
    """
    commits = {}
    bugs = {}
    for commit in range_revs:
        try:
            # Show git commit message and diff
            cmd_git_show = ['git', 'show', '-U0', '--format=%B', commit]
            o = subprocess.run(cmd_git_show, check=True, text=True, capture_output=True)
            # Split commit into message (what comes before 'diff --git ...')
            # and diff (what comes after, including 'diff --git ...')
            sep = 'diff --git'
            spl = o.stdout.strip().split(sep=sep, maxsplit=1)
            if not spl:
                print(f'Skipping empty commit {commit}', file=sys.stderr)
                continue
            c = Commit(commit, '', '')
            if len(spl) > 0:
                c.message = spl[0]
            if len(spl) > 1:
                c.diff = sep + spl[1]
            commits[commit] = c
        except subprocess.CalledProcessError as e:
            print(e, file=sys.stderr)
            continue

        # Extract bugs from commit message
        for b in set(re.findall(bug_regex, c.message)):
            if b not in bugs:
                bugs[b] = []
            bugs[b].append(f'message:{commit}')

        # Extract bugs from '+' lines in the commit diff
        for b in set(re.findall(bug_regex, c.lines_added())):
            if b not in bugs:
                bugs[b] = []
            bugs[b].append(f'diff:{commit}')
    return (commits, bugs)


def check_bug_status(bugid: str, bugzilla: str) -> (bool, bool):
    """Check if a bug exists and is public on BUGZILLA_URL.

    Returns a tuple (exists, public).
    """
    try:
        n = bugnum(bugid)
        r = requests.get(f'{bugzilla}/show_bug.cgi', params={'id': n})
        return (
            not all(s in r.text for s in MISSING_BUG_STRINGS),
            not all(s in r.text for s in PRIVATE_BUG_STRINGS),
        )
    except requests.exceptions.RequestException as e:
        print(e, file=sys.stderr)
        return False, False
    except ValueError as e:
        print(e, file=sys.stderr)
        return False, False


def detect_similar_bugs(bugs: dict[str, list]) -> int:
    """Detect similar bugs (typos, off-by-one, ...).

    Since this is not a deterministic check, only report warnings.

    Returns the number of printed warnings.
    """
    warnings = 0
    bugs2 = sorted(bugs.keys(), reverse=True)
    while len(bugs2) > 1:
        b = bugs2.pop(0)
        close_matches = set(difflib.get_close_matches(b, bugs2, cutoff=SIMILARITY_THRESHOLD))
        # Force detect substring bugs
        for e in bugs2:
            if bugnum(b) in e or bugnum(e) in b:
                close_matches.add(e)
        if close_matches:
            print(f'Warning:\t{b}\t(found in {bugs[b]}) closely matches:')
            for m in close_matches:
                print(f'\t\t{m}\t(found in {bugs[m]})')
            print()
            warnings += 1
    return warnings


def detect_nonexistent_nonpublic_bugs(bugs: dict[str, list], bugzilla: str, verbose: bool | int) -> (int, int):
    """Detect nonexistent or non-public bugs.

    Nonexistent bugs are reported as errors, while non-public bugs are reported as warnings.

    Returns a tuple (errors, warnings).
    """
    errors = 0
    warnings = 0
    for bugid, bug in bugs.items():
        exists, public = check_bug_status(bugid, bugzilla)
        if not exists:
            print(f'Error:\t\t{bugid}\t(found in {bug}) does not exist on {bugzilla}!')
            errors += 1
        elif verbose:
            print(f'Debug:\t\t{bugid}\t(found in {bug}) exists on {bugzilla}')
        if exists:
            if not public:
                print(f'Warning:\t{bugid}\t(found in {bug}) is not public on {bugzilla}!')
                warnings += 1
            elif verbose:
                print(f'Debug:\t\t{bugid}\t(found in {bug}) is public on {bugzilla}')
    return (errors, warnings)


def detect_removed_bug_refs(bugs: dict[str, list], commits: dict[str, list], bug_regex: re.Pattern) -> int:
    """Detect possible removal of bug references.

    Detect bugs which are mentioned in a '-' line and not in any '+' line of any commit.
    Since bugs could conceivably be removed for valid reasons, only report warnings.

    Returns the number of printed warnings.
    """
    warnings = 0
    # Extract bugs from '-' lines in the commit diff
    for commit, c in commits.items():
        for b in set(re.findall(bug_regex, c.lines_removed())):
            # If the bug is not mentioned in any '+' lines, report it as possibly being removed
            if b not in [x for x in bugs if any(s for s in bugs[x] if s.startswith('diff'))]:
                print(f'Warning:\t{b}\t is being removed in {commit}')
                warnings += 1
    return warnings


def detect_bad_hashes(commits: dict[str, list]) -> int:
    """Detect wrong-length SHA-256 hashes in '+' lines in commits.

    SHA-256 hashes must be 64 hexadecimal characters.

    Returns the number of bad hashes detected.
    """
    errors = 0

    for commit, c in commits.items():
        for ln in c.lines_added():
            # Strip leading '+' and any whitespace
            l = ln[1:].strip()
            if l.startswith('hash ='):
                # Extract hash value by stripping usual surrounding characters
                value = l.split(sep='=', maxsplit=1)[1].strip().strip('"\',')
                if len(value) != 64:
                    print(f'Error:\t\tInvalid hash length ({len(value)}, expected 64)')
                    print(f'\t\tin commit {commit}:')
                    print(ln)
                    errors += 1
    if errors:
        print()
    return errors

def main():
    parser = argparse.ArgumentParser(description='Check git commits for whitelisting consistency')
    parser.add_argument(
        '--from',
        type=str,
        dest='git_from',
        default=DEFAULT_FROM,
        help=f'The source Git identifier [Default: "{DEFAULT_FROM}"]',
    )
    parser.add_argument(
        '--to',
        type=str,
        dest='git_to',
        default=None,
        help='The target Git identifier [Default: unset]',
    )
    parser.add_argument(
        '-n',
        '--max-count',
        type=int,
        help='The number of commits to inspect [Default: not limited]',
    )
    parser.add_argument(
        '-t',
        '--title',
        type=str,
        help='An additional string to check (PR title)',
    )
    parser.add_argument(
        '-b',
        '--body',
        type=str,
        help='An additional string to check (PR body)',
    )
    parser.add_argument(
        '--bugzilla',
        type=str,
        default=DEFAULT_BUGZILLA_URL,
        help=f'A custom Bugzilla URL [Default: {DEFAULT_BUGZILLA_URL}]',
    )
    parser.add_argument(
        '--bug-tag',
        type=str,
        nargs='*',
        default=DEFAULT_BUG_TAGS,
        help=f'A tag by which to identify bug references (tag#xxx) [Default: {DEFAULT_BUG_TAGS}]',
    )
    parser.add_argument(
        '--strict',
        action='store_true',
        help='Treat warnings as errors [Default: False]',
    )
    parser.add_argument(
        '-v',
        '--verbose',
        action='count',
        help='Print increasingly verbose information [Up to 2 times, default: 0]',
        default=0,
    )

    args = parser.parse_args()

    # At least one of -n or --to must be provided, otherwise this will run on the entire Git history
    if not (args.max_count or args.git_to):
        print('Invalid commit range: at least one of --to or -n must be specified', file=sys.stderr)
        return 1

    # Validate Bugzilla URL
    args.bugzilla = validate_url(args.bugzilla)

    # Validate bug tags
    bug_tags = validate_bug_tags(args.bug_tag)
    if not bug_tags:
        print(f'No valid bug tags found (specified {args.bug_tag})', file=sys.stderr)
        return 1
    bug_regex = re.compile(f'(?:{"|".join(bug_tags)})#\\d+')

    # Get list of commits
    try:
        cmd_git_rev_list = ['git', 'rev-list']

        # Limit commit number if requested
        if args.max_count:
            cmd_git_rev_list.append(f'-n{args.max_count}')

        # If a destination ref has been provided, select the commit range between the source ref and the merge-base
        # between destination and source (the commits in the source "feature" branch)
        if args.git_to:
            cmd_git_merge_base = ['git', 'merge-base', args.git_to, args.git_from]
            o = subprocess.run(cmd_git_merge_base, check=True, text=True, capture_output=True)
            merge_base = o.stdout.strip()
            cmd_git_rev_list.append(f'{merge_base}..{args.git_from}')
        else:
            cmd_git_rev_list.append(args.git_from)

        # Obtain the selected list of commits
        o = subprocess.run(cmd_git_rev_list, check=True, text=True, capture_output=True)
        range_revs = o.stdout.strip().splitlines()
        if args.verbose:
            print(f'Commits in range ({len(range_revs)}):')
            print('\n'.join(range_revs))
            print()
    except subprocess.CalledProcessError as e:
        print(e, file=sys.stderr)
        print(e.stderr, file=sys.stderr)
        print(os.getcwd())
        return e.returncode

    # Extract data from commits
    commits, bugs = extract_commit_data(range_revs, bug_regex)

    if args.verbose > 1:
        print('Commits:')
        for _, v in commits.items():
            print(v)
            print()

    # Extract data from additional fields
    if args.title:
        for b in set(re.findall(bug_regex, args.title)):
            if b not in bugs:
                bugs[b] = []
            bugs[b].append('PR Title')
    if args.body:
        for b in set(re.findall(bug_regex, args.body)):
            if b not in bugs:
                bugs[b] = []
            bugs[b].append('PR Body')

    if args.verbose:
        print(f'Bugs ({len(bugs)}):')
        print(', '.join(bugs))
        print()

    #################################################################
    errors = 0
    warnings = 0

    # Detect similar bugs (typos, off-by-one, ...)
    warnings += detect_similar_bugs(bugs)

    # Detect nonexistent or non-public bugs
    e, w = detect_nonexistent_nonpublic_bugs(bugs, args.bugzilla, args.verbose)
    errors += e
    warnings += w

    # Detect possible removal of bug references
    warnings += detect_removed_bug_refs(bugs, commits, bug_regex)

    # Detect wrong-length SHA-256 hashes
    errors += detect_bad_hashes(commits)

    if args.verbose:
        print(f'\nErrors: {errors}\tWarnings: {warnings}')

    return errors + warnings if args.strict else errors


if __name__ == '__main__':
    sys.exit(main())

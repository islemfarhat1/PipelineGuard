
import re


def translate_line(old_line: int, diff: str) -> int | None:
    """
    Translate an old line number to its new position using Git diff hunks.

    Returns:
        int: New line number if the mapping is reliable.
        None: If the line was modified/deleted or mapping is unavailable.
    """

    # Git hunk examples:
    # @@ -3,1 +3,2 @@
    # @@ -3 +3,2 @@
    # @@ -1,0 +2,5 @@
        # Reject multi-file diffs until file-specific mapping is supported.
    if len(re.findall(r"^diff --git ", diff, flags=re.MULTILINE)) > 1:
        return None
    pattern = r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@"
    matches = list(re.finditer(pattern, diff))

    if not matches or old_line < 1:
     return None

    # Extract and validate every Git hunk before calculating line shifts.
    hunk_contents = extract_hunk_lines(diff, matches)

    for match, lines in zip(matches, hunk_contents):
        old_count = int(match.group(2) or 1)
        new_count = int(match.group(4) or 1)

        if not validate_hunk(old_count, new_count, lines):
            return None

    shift = 0
    previous_old_end = -1


    for match in matches:
        old_start = int(match.group(1))
        old_count = int(match.group(2) or 1)
        new_count = int(match.group(4) or 1)
        # Reject hunks that move backward or overlap.
        if old_start < previous_old_end:
            return None

        previous_old_end = old_start + old_count

        # Case 1: Pure insertion
        if old_count == 0:
            if old_line > old_start:
                shift += new_count
            continue

        # Case 2: Modified or deleted line
        # No reliable mapping is available.
        if old_start <= old_line < old_start + old_count:
            return None

        # Case 3: Line after a modified region
        # Accumulate the net shift.
        if old_line >= old_start + old_count:
            shift += new_count - old_count

    return old_line + shift



def validate_hunk(
    old_count: int,
    new_count: int,
    hunk_lines: list[str],
) -> bool:
    """Check that Git hunk content matches its declared line counts."""

    actual_old = 0
    actual_new = 0

    for line in hunk_lines:
        if line.startswith("+"):
            actual_new += 1

        elif line.startswith("-"):
            actual_old += 1

        elif line.startswith(" "):
            actual_old += 1
            actual_new += 1

        elif line == r"\ No newline at end of file":
            continue

        else:
            return False

    return actual_old == old_count and actual_new == new_count

def extract_hunk_lines(diff: str, matches: list) -> list[list[str]]:
    """Extract the content lines belonging to each Git diff hunk."""

    hunks = []

    for index, match in enumerate(matches):
        start = diff.find("\n", match.end())

        if start == -1:
            hunks.append([])
            continue

        start += 1

        if index + 1 < len(matches):
            end = matches[index + 1].start()
        else:
            end = len(diff)

        content = diff[start:end]
        hunks.append(content.splitlines())

    return hunks


def extract_file_diff(diff: str, target_file: str) -> str | None:
    """Extract the Git diff section for one specific file."""

    sections = re.split(r"(?=^diff --git )", diff, flags=re.MULTILINE)

    for section in sections:
        if not section.startswith("diff --git "):
            continue

        header = section.splitlines()[0]
        expected_header = f"diff --git a/{target_file} b/{target_file}"

        if header == expected_header:
            return section

    return None

from engine.line_mapping import translate_line
from engine.line_mapping import extract_file_diff

def test_inserted_lines_shift_existing_finding():
    # Git diff: five lines inserted after old line 1
    diff = (
    "@@ -1,0 +2,5 @@ def process_data(user_input):\n"
    "+    # Comment 1\n"
    "+    # Comment 2\n"
    "+    # Comment 3\n"
    "+    # Comment 4\n"
    "+    # Comment 5\n"
)

    assert translate_line(1, diff) == 1
    assert translate_line(2, diff) == 7
    assert translate_line(3, diff) == 8

def test_modified_lines_have_no_reliable_mapping():
    # Old lines 2-3 are replaced by one new line.
    diff = (
    "@@ -2,2 +2,1 @@\n"
    "-    old_instruction_1()\n"
    "-    old_instruction_2()\n"
    "+    new_instruction()\n"
)

    assert translate_line(2, diff) is None
    assert translate_line(3, diff) is None

def test_multiple_insertions_accumulate_line_shifts():
    # Two separate insertions, each adding two lines.
    diff = (
    "@@ -1,0 +2,2 @@\n"
    "+    # First insertion A\n"
    "+    # First insertion B\n"
    "@@ -10,0 +13,2 @@\n"
    "+    # Second insertion A\n"
    "+    # Second insertion B\n"
)

    # Old line 15 moves by four lines in total.
    assert translate_line(15, diff) == 19

def test_git_hunk_with_omitted_count():
    # Git may omit ",1" when a range contains one line.
    diff = (
    "@@ -3 +3,2 @@\n"
    "-    old_instruction()\n"
    "+    new_instruction()\n"
    "+    additional_instruction()\n"
)

    # Old line 3 was modified: no reliable mapping.
    assert translate_line(3, diff) is None

    # One extra line was introduced.
    assert translate_line(4, diff) == 5

def test_invalid_hunk_order_has_no_reliable_mapping():
    # The second hunk incorrectly goes backward in the old file.
    diff = (
    "@@ -10,0 +11,2 @@\n"
    "+    # First addition A\n"
    "+    # First addition B\n"
    "@@ -5,0 +6,1 @@\n"
    "+    # Second addition\n"
)

    # An inconsistent diff must not produce a trusted mapping.
    assert translate_line(15, diff) is None

def test_overlapping_hunks_have_no_reliable_mapping():
    diff = (
    "@@ -5,3 +5,2 @@\n"
    "-    old_line_5()\n"
    "-    old_line_6()\n"
    "-    old_line_7()\n"
    "+    new_line_5()\n"
    "+    new_line_6()\n"
    "@@ -7,2 +6,1 @@\n"
    "-    old_line_7()\n"
    "-    old_line_8()\n"
    "+    replacement()\n"
)

    assert translate_line(12, diff) is None

def test_deleted_lines_and_following_shift():
    diff = (
    "@@ -5,3 +4,0 @@\n"
    "-    old_line_1()\n"
    "-    old_line_2()\n"
    "-    old_line_3()\n"
)

    assert translate_line(4, diff) == 4
    assert translate_line(5, diff) is None
    assert translate_line(6, diff) is None
    assert translate_line(7, diff) is None
    assert translate_line(8, diff) == 5

def test_incomplete_git_diff_has_no_reliable_mapping():
    diff = (
        "@@ -2,0 +3,2 @@\n"
        "+    # Only one added line\n"
    )

    assert translate_line(5, diff) is None

def test_multifile_diff_does_not_mix_hunk_contents():
    diff = (
        "diff --git a/demo.py b/demo.py\n"
        "--- a/demo.py\n"
        "+++ b/demo.py\n"
        "@@ -2,0 +3,1 @@\n"
        "+    # New comment\n"
        "diff --git a/config.py b/config.py\n"
        "--- a/config.py\n"
        "+++ b/config.py\n"
        "@@ -1,0 +2,1 @@\n"
        "+    # Another comment\n"
    )

    assert translate_line(5, diff) is None

    from engine.line_mapping import extract_file_diff


def test_extract_specific_file_from_multifile_diff():
    diff = (
        "diff --git a/demo.py b/demo.py\n"
        "--- a/demo.py\n"
        "+++ b/demo.py\n"
        "@@ -2,0 +3,1 @@\n"
        "+    # New comment\n"
        "diff --git a/config.py b/config.py\n"
        "--- a/config.py\n"
        "+++ b/config.py\n"
        "@@ -1,0 +2,1 @@\n"
        "+    # Another comment\n"
    )

    result = extract_file_diff(diff, "demo.py")

    assert result is not None
    assert "diff --git a/demo.py b/demo.py" in result
    assert "+    # New comment" in result
    assert "diff --git a/config.py b/config.py" not in result


def test_extract_then_translate_line():
    diff = (
        "diff --git a/demo.py b/demo.py\n"
        "--- a/demo.py\n"
        "+++ b/demo.py\n"
        "@@ -2,0 +3,1 @@\n"
        "+    # New comment\n"
        "diff --git a/config.py b/config.py\n"
        "--- a/config.py\n"
        "+++ b/config.py\n"
        "@@ -1,0 +2,1 @@\n"
        "+    # Another comment\n"
    )

    file_diff = extract_file_diff(diff, "demo.py")

    assert file_diff is not None
    assert translate_line(5, file_diff) == 6
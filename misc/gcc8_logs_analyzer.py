# Copyright 2025, Bayerische Motoren Werke Aktiengesellschaft (BMW AG)

import re
import sys

# Global regex patterns
ERROR_PATTERN = re.compile(r'^(.*?):(\d+):(\d+):\s+error:\s+(.*)$')
# Matches common C++20 keywords (case-insensitive)
LANG_SPECIFIC_REGEX = re.compile(
    r'\b(concept|requires|co_await|co_yield|co_return|consteval|constinit)\b',
    re.IGNORECASE
)
# Matches the phrase "is not a member of std" (allowing for variations in quotes)
STL_FEATURE_REGEX = re.compile(
    r"is not a member of\s+[‘']?std[’']?",
    re.IGNORECASE
)
# Captures the STL feature name that is reported missing (expects the feature to be in quotes)
STL_FEATURE_CAPTURE_REGEX = re.compile(
    r"[‘'](\w+)[’']\s+is not a member of\s+[‘']?std[’']?",
    re.IGNORECASE
)

class ReportBuilder:
    def __init__(self, grouped=False):
        self.lines = []
        self.grouped = grouped
        self.group_level = 0

    def add_tab(self):
        return "\t" * self.group_level
    def begin_group(self, title):
        if self.grouped:
            self.add_line(f"::group::{title}")
        else:
            self.add_line(f"{title}")
        self.group_level += 1

    def end_group(self):
        self.group_level -= 1
        if self.grouped and self.group_level >= 0:
            self.add_line("::endgroup::")

    def add_line(self, line):
        self.lines.append(f"{self.add_tab()}{line}")

    def get_report(self):
        # Close any open groups
        while self.group_level > 0:
            self.end_group()
        return "\n".join(self.lines)

def parse_gcc_log(log_path):
    errors = []
    with open(log_path, 'r') as f:
        for line in f:
            line = line.strip()
            match = ERROR_PATTERN.match(line)
            if match:
                filename, line_no, col, message = match.groups()
                # Check for language-specific keywords.
                is_lang_specific = bool(LANG_SPECIFIC_REGEX.search(message))
                # Check if the error message indicates a missing member of std.
                is_stl_specific = bool(STL_FEATURE_REGEX.search(message))
                errors.append({
                    'filename': filename,
                    'line': int(line_no),
                    'column': int(col),
                    'message': message,
                    'language_specific': is_lang_specific,
                    'stl_specific': is_stl_specific
                })
    return errors
def generate_report(errors, grouped=False, details_in_group=False):

    # Categorize errors.
    lang_specific_errors = [e for e in errors if e['language_specific']]
    stl_specific_errors = [e for e in errors if e['stl_specific']]
    general_errors = [e for e in errors if not e['language_specific'] and not e['stl_specific']]

    missing_lang_features = set()
    for e in lang_specific_errors:
        features = LANG_SPECIFIC_REGEX.findall(e['message'])
        for f in features:
            missing_lang_features.add(f.lower())

    missing_stl_features = set()
    for e in stl_specific_errors:
        match = STL_FEATURE_CAPTURE_REGEX.search(e['message'])
        if match:
            missing_stl_features.add(match.group(1).lower())

    builder = ReportBuilder(grouped)

    # Summary lines
    builder.add_line("GCC Error Log Report")
    builder.add_line("====================")
    builder.add_line(f"Total Errors: {len(errors)}")

    if lang_specific_errors:
        builder.add_line(f" Language-Specific Errors: {len(lang_specific_errors)}")
        builder.add_line("      Missing Language Features")
        for feature in sorted(missing_lang_features):
            builder.begin_group(f"{feature}: {len([e for e in lang_specific_errors if feature in e['message'].lower()])} errors")
            if details_in_group:
                for err in [e for e in lang_specific_errors if feature in e['message'].lower()]:
                    builder.add_line(f"{err['filename']}:{err['line']}:{err['column']}: {err['message']}")
            builder.end_group()

    if stl_specific_errors:
        builder.add_line(f"  STL-Specific Errors: {len(stl_specific_errors)}")
        builder.add_line("       Missing STL Features")
        for feature in sorted(missing_stl_features):
            builder.begin_group(f"{feature}: {len([e for e in stl_specific_errors if feature in e['message'].lower()])} errors")
            if details_in_group:
                for err in [e for e in stl_specific_errors if feature in e['message'].lower()]:
                    builder.add_line(f"{err['filename']}:{err['line']}:{err['column']}: {err['message']}")
            builder.end_group()

    if general_errors:
        builder.begin_group(f"General Errors: {len(general_errors)}")
        if details_in_group:
            for err in general_errors:
                builder.add_line(f"{err['filename']}:{err['line']}:{err['column']}: {err['message']}")
        builder.end_group()

    # Show details if not already shown in groups
    if not details_in_group:
        if lang_specific_errors:
            builder.begin_group("Language-Specific Errors Details")
            for err in lang_specific_errors:
                builder.add_line(f"{err['filename']}:{err['line']}:{err['column']}: {err['message']}")
            builder.end_group()
        if stl_specific_errors:
            builder.begin_group("STL-Specific Errors Details")
            for err in stl_specific_errors:
                builder.add_line(f"{err['filename']}:{err['line']}:{err['column']}: {err['message']}")
            builder.end_group()
        if general_errors:
            builder.begin_group("General Errors Details")
            for err in general_errors:
                builder.add_line(f"{err['filename']}:{err['line']}:{err['column']}: {err['message']}")
            builder.end_group()

    builder.end_group()
    return builder.get_report()

def main():
    grouped = False
    details_in_group = False
    args = [a for a in sys.argv[1:] if a != '--on-github']
    if '--on-github' in sys.argv:
        grouped = True
        details_in_group = True
    if len(args) < 1:
        print("Usage: python gcc8_logs_analyzer.py <gcc_output_log_file> [--on-github]")
        sys.exit(1)

    log_file = args[0]
    errors = parse_gcc_log(log_file)
    report = generate_report(errors, grouped=grouped, details_in_group=details_in_group)
    print(report)

if __name__ == "__main__":
    main()

# Lessons

## 2026-10-26: Pillow security update

- Symptom: GitHub flagged Pillow 12.3.0 in `uv.lock` for CVE-2026-112896.
- Root cause: The lockfile retained an affected version; the previous August release cutoff excluded the patched October release.
- Fix: Move the cutoff to 19 October 2026 and regenerate the lockfile targeting Pillow 13.0.0. Lockfile consistency validation passed.
- Lesson: Changing a release cutoff only permits newer packages; explicitly update the affected locked dependency, verify resolution, and sync each runtime environment separately.

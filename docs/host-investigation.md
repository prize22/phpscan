# Host investigation (phpscan 0.4.0)

`phpscan investigate` audits the on-disk neighborhood of a PHP surface.
It is read-only: nothing is moved, renamed, deleted, or written.

## What it looks for

| category | meaning |
|---|---|
| `DISGUISED_PHP` | non-PHP file containing PHP markers (`<?php`, `<?=` in plain content) |
| `DOUBLE_EXTENSION` | `shell.php.jpg` and friends |
| `HIDDEN_PHP` | dot-named PHP files (`.config.php`) |
| `BACKUP_ARTIFACT` | `.bak/.old/.copy/.save/.orig/.swp` or trailing `~` |
| `CONFIG_FILE` | known config filenames; body secret-scanned |
| `LOG_FILE` | `*.log`, `error_log`, `debug.log`; secret-scanned (first 64 KB) |
| `PHP_LOCATION_NOTED` | PHP files in upload-ish directories or unusual extensions |
| `EMPTY_PHP` | zero-byte PHP file |
| `RECENT_FILE` | mtime inside the recent window (`--recent-days`, default 30) |
| `PERSISTENCE_CANDIDATE` | presence of `wp-content/mu-plugins` (and on POSIX, cron/systemd paths under root) |
| `PROCESS_OBSERVED` | interpreter process lines (only with `--processes`) |

## Crash-proof by construction

- Binary content stays binary: PNG headers, anything with a NUL byte in
  the header block, is skipped for marker sniffing.
- Non-PHP files are searched head+tail (16 KB each) only; large frames
  do not blow the budget.
- All output is Evidence records (origin=host); conclusion drawing
  happens in fusion, not here. Records carry `mtime`/`size` refs.

## Production caution notes

- `--processes` is opt-in. On Windows it shells `wmic process get
  ProcessId,CommandLine`; on POSIX it reads `/proc/<pid>/cmdline`.
- Evidence stores secrets as redacted hashes; the original never leaves
  the machine because reports only carry `redacted=True` objects.

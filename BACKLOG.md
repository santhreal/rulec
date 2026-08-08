# BACKLOG - rulec

Seeded 2026-07-14 (main-thread audit). One-way YARA→vyre rule compiler. Exemplary discipline: every unsupported construct is rejected loudly with what/why/fix (never a silent subset), condition consumers are exhaustive matches (ONE PLACE), and the differential oracle counts every skip. Rows: `number | affected files | problem | acceptance criteria`.

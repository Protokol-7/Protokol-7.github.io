---
title: "WAL Carving in Windows Search Index Forensics, Patching SIDR and SQLECmd Decoding Support"
date: 2026-10-27 00:00:00 +0000
author: "Mato Vlajčić, Luka Bračun, and Dino Bezić"
categories: [dfir]
tags: [sidr, sqlecmd, windows-search, sqlite-forensics, wal-carving]
---

If you've worked a case involving the Windows Search index, you've probably used either SIDR or EZ-Tools' SQLECmd to pull it apart. Recently we wanted to create support for WAL carving and we noticed SIDR doesn't work on Windows versions 24H2/25H2, so we ended up fixing it, building a new recovery feature onto it, and writing a decoder to make SQLECmd's output actually usable.

Starting point for the SIDR work: their main branch at commit `5bde8e8`. Worth flagging that this is 158 commits past `v0.9.2`, the last tag they cut. SIDR still reports itself as `v0.9.2` even though main has moved on quite a bit since.

## SIDR didn't work on 24H2/25H2 at all

Point stock SIDR at a Windows 11 24H2 or 25H2 database and it fails, before it even gets to reading rows. A couple of its value decoders also choke on how newer builds store a handful of columns. We patched both problems. Reports now come out byte-identical to stock SIDR's on the older databases it already handled fine. We didn't touch existing behavior, just stopped it from falling over on newer ones.

## Recovering what the live database can't show you - WAL Carving

Here's the thing about reading a SQLite database normally, whether that's through SIDR, SQLECmd, or `sqlite3` itself: you only ever get the current, committed state of each row. SQLite was built that way on purpose. Anything a later write replaced or deleted simply stops being part of what a `SELECT` returns.

Except it's often still sitting right there on disk. `Windows.db` runs in WAL mode, meaning writes don't happen in place: SQLite appends a new copy of the changed page to the `-wal` file, and a query is answered by walking backward through the WAL for the newest version of each page, falling back to the main database file for anything the WAL hasn't touched. Until a checkpoint folds all of that back into the main file, the previous version of every changed page is still physically present as an earlier WAL frame. And even pages in the main `.db` file that look "replaced" or "unused" from SQLite's point of view often still hold their old contents; SQLite has simply stopped referencing them from the current page tree.

None of that is reachable through the normal query interface. So we built the only thing that could reach it: a module (src/carve.rs) that reads the WAL and the database file byte by byte, ignoring SQLite's API entirely, and reconstructs page history from the raw bytes. Roughly, it works like this:

1. **Read the WAL frame by frame.** Each frame starts with a 24-byte header (page number, commit marker, salt, checksum) followed by a full page image. The checksum chains across the whole file, so if the chain is valid up through frame _N_, you know every frame up to _N_ genuinely belongs there. Frames get grouped by salt into "generations," since SQLite restarts the WAL from scratch (new salt) after a checkpoint, and two generations can both have a frame for the same page number sitting at completely different offsets.
2. **Figure out what each frame actually is**: part of a finished transaction, part of an unfinished one (checksum chain still valid, just no commit marker yet; this includes frames whose salt and checksum are still zero, which happens when a transaction overwrites its own earlier frame and only backfills the checksum once it commits), left over from an older generation, or just corrupt.
3. **Answer "what did page N look like at this point in time."** Given a generation and a frame index, look up the newest WAL frame for that page at or before that index, or fall back to the database file if the WAL never touched it. That's what lets the carver reconstruct a coherent page image (overflow pages included) for any point in the WAL's history, not just the current one.
4. **Walk the property store's b-tree in every page image you can find**: every WAL frame and every page of the database file, live or not, decoding `(WorkId, ColumnId, Value)` records and following overflow chains for values too big to fit on one page.
5. **Throw away anything that matches the current state.** Each decoded value gets hashed and compared against what's actually in the database right now for that WorkId/ColumnId. Only the ones that differ get reported, so you don't end up with the same unchanged value repeated across fifty page copies.
6. **Don't confuse it with a different table.** Freed pages from `SystemIndex_1_Properties`, an internal table with the same record shape as the property store, show up in this scan too. We tell them apart by checking whether every key on the page belongs to that table's small set of property IDs, every value is a blob, and at least one record sits under a key that would never be a blob in a real property-store page. Pages that match get reported separately and labelled "Not file data" rather than silently dropped or mixed in with real file records.

The output lands in a new report alongside SIDR's usual ones: `<HOSTNAME>_Recovered_Values_Report_<timestamp>`, so none of this gets quietly merged into the normal results. Each row tells you the property, the recovered value, what the current value is (if there is one), where the recovered value came from (WAL committed, WAL uncommitted, WAL from an old generation, a replaced DB page, an unused DB page), and what happened to the record itself: still there with a changed value, had a property removed, or deleted entirely.

## Where this actually matters on a case

The honest answer is "whenever something changed in a way the suspect, or the malware, didn't want you to see." A few scenarios where that's exactly what `--history` is for:

- **A file got deleted and the trail should've gone cold.** The Recycle Bin is empty, the MFT entry is gone, maybe the whole volume got wiped with a tool that's thorough about it, but Windows Search had already indexed the file while it existed. Once the index itself catches up and drops that record, a normal parse (SIDR, SQLECmd, whatever) shows nothing, because as far as the live database is concerned that WorkId never existed. `--history` can still pull the deleted record's last known path, name and dates back out of the WAL or a freed page, which is often the only artifact left proving the file was ever there at all.
- **Timestamps got tampered with.** Timestomping changes a file's dates on disk, and Windows Search dutifully reindexes the new values, overwriting whatever it had before. The pre-tamper timestamp is usually still sitting in an older WAL frame or a page the newer write replaced. Recovering it gives you something to compare the tampered value against, instead of just taking the current (manipulated) date at face value.
- **A file was renamed or moved to hide it.** Rename a sensitive file to something boring before copying it off, and the index just updates in place. The old name is gone from a live query the moment that happens. It's not gone from disk yet, though, and carving can recover it.

These map onto the report's `Status` column: the deleted-file case shows up as `Record deleted`, timestomping and renames both show up as `Changed` (the property still exists, it just used to hold a different value). `Property removed` is the fourth case: a property that existed on a record and later got cleared entirely, not replaced with something else.

A few honest caveats, because this isn't magic:

- It can only recover what's still physically there. If a page got overwritten _again_ after the version you'd want, or SQLite reused that database page for something else, it's gone for good.
- We're only carving whole pages that are unused or replaced: a deleted record sitting inside a page that's still otherwise live (what SQLite calls a "freeblock") doesn't get pulled out.
- WAL frames don't carry their own timestamps, so ordering is based on frame position and the WAL's commit structure, not wall-clock time.
- Windows Search can and does reuse a WorkId for a completely different item later, so before you treat a recovered value as "the history of file X," check it against the item path and any recovered date properties.

As for whether it actually works: we tested it against generated databases with a known edit history (renames, a deleted record, a removed property, a changed date, a value that spans multiple pages, an interrupted write, an old WAL generation) and checked the output against an independent oracle that rebuilds the database as of every committed WAL transaction using plain SQLite. We also ran it against a real 25H2 database and cross-checked it against an independent SQLECmd-based decode. Every value the oracle found, we found too, and we didn't report anything from a committed source that the oracle disagreed with.

## Making SQLECmd's output readable

SQLECmd parses the database fine. The problem is what it hands you back. A lot of the property-store output comes out as raw hex, which is technically correct and practically useless unless you want to decode every value by hand.

We wrote a script, `winsearch_decode.py`, to fix that. Point it at a folder of SQLECmd's CSV output and it finds the `SystemIndex_1_PropertyStore_Metadata` CSV on its own, uses it to figure out what each `ColumnId` actually is and what type it's supposed to hold, then scans every other CSV for columns that look like hex and adds a decoded column right next to each one. Nothing gets overwritten: the original hex stays, the decoded value sits beside it. It also builds a timeline out of the PropertyStore CSV: one row per item, decoded properties laid out as columns.

Decoding isn't as simple as "hex in, string out," because the property store doesn't store things consistently. A few of the quirks the script has to work around:

- Some values typed as numbers or dates are stored as literal ASCII text instead of binary (`0x38323039` is literally the bytes `"8209"`), so it checks for that before trying anything else.
- Dates are little-endian `FILETIME`s (100-nanosecond ticks since January 1, 1601) and get decoded into UTC.
- Strings are mostly UTF-8, but sometimes UTF-16LE, so the script probes for the telltale alternating-null-byte pattern before falling back to UTF-8.
- Some values are arrays packed into one blob, or integers stored in fewer bytes than their declared type would suggest, and both get unpacked using the width the metadata gives for that column.
- CLSID/GUID values get parsed out as actual GUIDs.
- When there's no metadata for a column at all, it falls back to guessing: try text first, then infer from the blob's length, and if nothing fits, just leave it as hex.

It only works from SQLECmd's CSV output, not against `Windows.db` directly: run SQLECmd first, then point this script at its output.

We checked this one against SIDR too, leaving out the `--history` recovery since neither SQLECmd nor stock SIDR has anything to compare it against. Every value stock SIDR produced showed up in our script's decoded output as well.

## So, bottom line

A normal read of a SQLite database, no matter how good the tool doing the reading is, can only ever show you what's there right now. If you want what used to be there, you have to go around the query interface entirely and carve the raw pages yourself; there's no decoding trick that gets you there from the current `.db` file alone. And tooling breaking on a new Windows build isn't rare. 24H2/25H2 took SIDR out before any of this recovery work even became relevant. Readable output matters too, for what it's worth: a technically correct hex value nobody can read quickly is still a bottleneck in the middle of an investigation.

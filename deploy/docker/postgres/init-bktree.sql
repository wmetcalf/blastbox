-- blastbox: enable pg_bktree once at database-init time so SqlJobStore can
-- declare an SP-GiST index on int8 phashes (bktree_ops operator class) for fast
-- Hamming-distance similarity search. See https://github.com/evirma/pg_bktree.
--
-- This is the ONLY thing a deployment must provide: the store creates its own
-- helper functions (hamming_distance, colorhash_bin_distance) at connect time
-- via CREATE OR REPLACE, so it depends on the extension alone, not on this script.
CREATE EXTENSION IF NOT EXISTS bktree;

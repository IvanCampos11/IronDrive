-- Older versions recorded a new event on every scan, so a single damaged file
-- could have dozens of open alerts. Keep the first (original detection) and
-- dismiss the copies.
UPDATE integrity_events
SET acknowledged = 1
WHERE acknowledged = 0
  AND rowid NOT IN (
    SELECT MIN(rowid)
    FROM integrity_events
    WHERE acknowledged = 0
    GROUP BY target_type, target_id, file_path, event_type
  );

-- At most one open alert per file and problem, even if two scans race.
CREATE UNIQUE INDEX IF NOT EXISTS idx_integrity_open_unique
    ON integrity_events(target_type, target_id, file_path, event_type)
    WHERE acknowledged = 0;

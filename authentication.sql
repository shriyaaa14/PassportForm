-- Run once against the PassportForm database before starting the application.
-- This also fixes existing tables whose password column is numeric (for example,
-- BIGINT), which otherwise coerces password hashes to 0.
-- Existing values already stored as 0 cannot be recovered; those accounts must
-- be registered again after this migration.
ALTER TABLE `authentication`
    MODIFY COLUMN `username` VARCHAR(100) NOT NULL,
    MODIFY COLUMN `password` VARCHAR(255) NOT NULL,
    ADD UNIQUE KEY `uq_authentication_username` (`username`);

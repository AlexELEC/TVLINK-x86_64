PRAGMA foreign_keys = off;
BEGIN TRANSACTION;

-- Table: channels
DROP TABLE IF EXISTS channels;
CREATE TABLE channels (chID BLOB, chTitle BLOB, chGroup BLOB, chLogo BLOB, chBinds BLOB, chSplit BOOLEAN, chExist BOOLEAN, chNum BLOB, chEPG_auto BLOB, chEPG_hand BLOB);

-- Table: groups
DROP TABLE IF EXISTS groups;
CREATE TABLE groups (grpID BLOB, grpTitle BLOB, enabled BOOLEAN, chBinds BLOB, grpNum BLOB, grpAlias BLOB);

COMMIT TRANSACTION;
PRAGMA foreign_keys = on;

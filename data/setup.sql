PRAGMA foreign_keys = off;
BEGIN TRANSACTION;

-- Table: epg_groups
DROP TABLE IF EXISTS epg_groups;
CREATE TABLE epg_groups (grpName BLOB, enabled BOOLEAN DEFAULT (0));
INSERT INTO epg_groups (grpName, enabled) VALUES ('Static', 0);
INSERT INTO epg_groups (grpName, enabled) VALUES ('User', 0);

-- Table: epg_sources
DROP TABLE IF EXISTS epg_sources;
CREATE TABLE epg_sources (srcName BLOB UNIQUE, enabled BOOLEAN DEFAULT (0), grpName BLOB, prio INT DEFAULT (10) NOT NULL, xmlDate BLOB, updDate BLOB, srcUrl BLOB, noDate BLOB, links INT DEFAULT (0) NOT NULL);
INSERT INTO epg_sources (srcName, enabled, grpName, prio, xmlDate, updDate, srcUrl, noDate, links) VALUES ('IptvxONE', 0, 'Static', 1, '', '', 'https://epgx.site/epg.xml.gz', '', 0);
INSERT INTO epg_sources (srcName, enabled, grpName, prio, xmlDate, updDate, srcUrl, noDate, links) VALUES ('IptvxTV', 0, 'Static', 2, '', '', 'http://epg.g-cdn.app/xmltv.xml.gz', '', 0);
INSERT INTO epg_sources (srcName, enabled, grpName, prio, xmlDate, updDate, srcUrl, noDate, links) VALUES ('EdemTV', 0, 'Static', 3, '', '', 'http://epg.it999.ru/edem.xml.gz', '', 0);
INSERT INTO epg_sources (srcName, enabled, grpName, prio, xmlDate, updDate, srcUrl, noDate, links) VALUES ('EpgTODAY', 0, 'Static', 4, '', '', 'http://downloads.epg.today/free/FreeRu-Cis.xml.gz', '', 0);

-- Table: input_groups
DROP TABLE IF EXISTS input_groups;
CREATE TABLE input_groups (grpName BLOB, enabled BOOLEAN DEFAULT (0));
INSERT INTO input_groups (grpName, enabled) VALUES ('Addons', 0);
INSERT INTO input_groups (grpName, enabled) VALUES ('Playlists', 0);

-- Table: input_sources
DROP TABLE IF EXISTS input_sources;
CREATE TABLE input_sources (srcName BLOB UNIQUE, enabled BOOLEAN DEFAULT (0), grpName BLOB, prio INT DEFAULT (10) NOT NULL, catchUp BLOB, addCh BOOLEAN DEFAULT (0), updPeriod INT DEFAULT (8) NOT NULL, updDate BLOB, links INT DEFAULT (0) NOT NULL, srcUrl BLOB, newCh BOOLEAN DEFAULT (0), maxStrm INT DEFAULT (0) NOT NULL);

-- Table: live_links
DROP TABLE IF EXISTS live_links;
CREATE TABLE live_links (uLink BLOB UNIQUE, disabled BOOLEAN, live BOOLEAN);

-- Table: settings
DROP TABLE IF EXISTS settings;
CREATE TABLE settings (name BLOB, value BLOB);
INSERT INTO settings (name, value) VALUES ('ip', NULL);
INSERT INTO settings (name, value) VALUES ('port', NULL);
INSERT INTO settings (name, value) VALUES ('auto_ip', NULL);
INSERT INTO settings (name, value) VALUES ('ch_sort', NULL);
INSERT INTO settings (name, value) VALUES ('upd_ch_start', NULL);
INSERT INTO settings (name, value) VALUES ('upd_ch_list', NULL);
INSERT INTO settings (name, value) VALUES ('del_ch', NULL);
INSERT INTO settings (name, value) VALUES ('auth_webui', NULL);
INSERT INTO settings (name, value) VALUES ('webui_user', NULL);
INSERT INTO settings (name, value) VALUES ('webui_pass', NULL);
INSERT INTO settings (name, value) VALUES ('usr_agent', NULL);
INSERT INTO settings (name, value) VALUES ('chunk_size', NULL);
INSERT INTO settings (name, value) VALUES ('ring_buffer', NULL);
INSERT INTO settings (name, value) VALUES ('http_timeout_connect', NULL);
INSERT INTO settings (name, value) VALUES ('http_timeout_data', NULL);
INSERT INTO settings (name, value) VALUES ('segment_timeout_connect', NULL);
INSERT INTO settings (name, value) VALUES ('segment_timeout_data', NULL);
INSERT INTO settings (name, value) VALUES ('stream_timeout', NULL);
INSERT INTO settings (name, value) VALUES ('hls_threshold', NULL);
INSERT INTO settings (name, value) VALUES ('stream_retry', NULL);
INSERT INTO settings (name, value) VALUES ('hls_live_edge', NULL);
INSERT INTO settings (name, value) VALUES ('stream_segment_threads', NULL);
INSERT INTO settings (name, value) VALUES ('segments_queue', NULL);
INSERT INTO settings (name, value) VALUES ('stream_data', NULL);
INSERT INTO settings (name, value) VALUES ('hls_playlist_reload_time', NULL);
INSERT INTO settings (name, value) VALUES ('hls_restart', NULL);
INSERT INTO settings (name, value) VALUES ('dbg_stream', NULL);
INSERT INTO settings (name, value) VALUES ('src_proxy', NULL);
INSERT INTO settings (name, value) VALUES ('epg_sort', NULL);
INSERT INTO settings (name, value) VALUES ('epg_enabled', NULL);
INSERT INTO settings (name, value) VALUES ('epg_period', NULL);
INSERT INTO settings (name, value) VALUES ('check_time', NULL);
INSERT INTO settings (name, value) VALUES ('check_net_ip', NULL);
INSERT INTO settings (name, value) VALUES ('extm3u', NULL);
INSERT INTO settings (name, value) VALUES ('extinf', NULL);
INSERT INTO settings (name, value) VALUES ('exclude_title', NULL);

COMMIT TRANSACTION;
PRAGMA foreign_keys = on;

CREATE TABLE IF NOT EXISTS users (
	id BLOB NOT NULL DEFAULT randomblob(16) PRIMARY KEY,
	email TEXT NOT NULL,
	password BLOB NOT NULL,
	salt BLOB NOT NULL,
	token TEXT,
	lang TEXT DEFAULT 'en',
	created DATETIME NOT NULL DEFAULT datetime('now'),
	emailSent DATETIME,
	activated DATETIME
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_email
    ON users(email);
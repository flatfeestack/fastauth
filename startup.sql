DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS users (
	id BLOB NOT NULL DEFAULT(randomblob(16)) PRIMARY KEY,
	email TEXT NOT NULL,
	role TEXT NOT NULL,
	password BLOB NOT NULL,
	salt BLOB NOT NULL,
	refreshToken TEXT NOT NULL DEFAULT(lower(hex(randomblob(16)))),
	emailToken TEXT,
	lang TEXT DEFAULT 'en',
	created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	emailSent DATETIME,
	activated DATETIME
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_email
    ON users(email);

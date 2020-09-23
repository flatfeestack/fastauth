DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS users (
	email TEXT PRIMARY KEY,
	sms TEXT,
	role TEXT NOT NULL,
	password BLOB NOT NULL,
	salt BLOB NOT NULL,
	refreshToken TEXT NOT NULL,
	emailToken TEXT,
	forgetEmailToken TEXT,
	totp TEXT,
	lang TEXT DEFAULT 'en',
	created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	emailSent TIMESTAMP,
	emailVerified TIMESTAMP,
	smsVerified TIMESTAMP,
	totpVerified TIMESTAMP,
	forgetEmail TIMESTAMP,
	errorCount INT(255) DEFAULT 0
);

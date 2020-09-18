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
	forgetEmail TIMESTAMP
);

#INSERT INTO users (email, sms, role, password, salt, refreshToken, emailToken, forgetEmailToken, totp, lang, created, emailSent, emailVerified, smsVerified, totpVerified, forgetEmail) VALUES ('tom@test.ch', null, 'USR', X'0A139279851C25AACB8E4A8206FC8826B1268C661D0D64750E04ADD13CE4109B', X'7E37E2DC137E985C4F445DE008BF270C', X'608caa5d93cac281a29cbee0d134a724', null, null, null, 'en', '2020-09-14 16:35:15', '2020-09-14 16:35:15', '2020-09-14 16:35:15', null, null, null);

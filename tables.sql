CREATE TABLE `entities` (
    id INT PRIMARY KEY NOT NULL AUTO_INCREMENT,
    name VARCHAR(128) UNIQUE,
    password VARBINARY(32) COMMENT "SHA256",
    registration_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ed25519_private VARBINARY(32) COMMENT "AES256",
    ed25519_public VARBINARY(32),
    x25519_private VARBINARY(32) COMMENT "AES256",
    x25519_public VARBINARY(32)
);


CREATE TABLE  IF NOT EXISTS http_sessions (
  -- PRIMARY_ID CHAR(36) NOT NULL,
  session_id CHAR(36) NOT NULL,
  creation_time BIGINT NOT NULL,
  last_access_time BIGINT NOT NULL,
  max_inactive_interval INT,
  expiry_time BIGINT,
  alias INT NOT NULL,
  principal_name VARCHAR(100),
  CONSTRAINT http_sessions_pk PRIMARY KEY (session_id )
);

create unique index  IF NOT EXISTS http_session_ix1 on http_sessions (session_id);
-- create index  IF NOT EXISTS http_session_ix2 on http_sessions (expiry_time);
create index  IF NOT EXISTS http_session_ix3 on http_sessions (principal_name);

CREATE TABLE  IF NOT EXISTS http_session_principals (
  session_id CHAR(36) NOT NULL,
  alias INT NOT NULL,
  principal_name VARCHAR(100) NOT NULL,
  CONSTRAINT http_session_principals_pk PRIMARY KEY (session_id, principal_name),
  CONSTRAINT http_session_principals_fk FOREIGN KEY (session_id) REFERENCES http_sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX  IF NOT EXISTS http_session_principals_ix1 ON http_session_principals (session_id);


-- CREATE TABLE SPRING_SESSION (
--   -- PRIMARY_ID CHAR(36) NOT NULL,
--   SESSION_ID CHAR(36) NOT NULL,
--   CREATION_TIME BIGINT NOT NULL,
--   LAST_ACCESS_TIME BIGINT NOT NULL,
--   MAX_INACTIVE_INTERVAL INT,
--   EXPIRY_TIME BIGINT,
--   PRINCIPAL_NAME VARCHAR(100),
--   CONSTRAINT SPRING_SESSION_PK PRIMARY KEY (SESSION_ID )
-- );
 
-- CREATE UNIQUE INDEX SPRING_SESSION_IX1 ON SPRING_SESSION (SESSION_ID);
-- CREATE INDEX SPRING_SESSION_IX2 ON SPRING_SESSION (EXPIRY_TIME);
-- CREATE INDEX SPRING_SESSION_IX3 ON SPRING_SESSION (PRINCIPAL_NAME);
 
-- CREATE TABLE SPRING_SESSION_ATTRIBUTES (
--   SESSION_ID  CHAR(36) NOT NULL,
--   ATTRIBUTE_NAME VARCHAR(200) NOT NULL,
--   ATTRIBUTE_BYTES LONGVARBINARY NOT NULL,
--   CONSTRAINT SPRING_SESSION_ATTRIBUTES_PK PRIMARY KEY (SESSION_ID, ATTRIBUTE_NAME),
--   CONSTRAINT SPRING_SESSION_ATTRIBUTES_FK FOREIGN KEY (SESSION_ID) REFERENCES SPRING_SESSION(SESSION_ID) ON DELETE CASCADE
-- );
 
-- CREATE INDEX SPRING_SESSION_ATTRIBUTES_IX1 ON SPRING_SESSION_ATTRIBUTES (SESSION_ID);
--
--
--
CREATE TABLE IF NOT EXISTS oauth_client_details (
  client_id VARCHAR(256) PRIMARY KEY,
  resource_ids VARCHAR(256),
  client_secret VARCHAR(256) NOT NULL,
  scope VARCHAR(256),
  authorized_grant_types VARCHAR(256),
  web_server_redirect_uri VARCHAR(256),
  authorities VARCHAR(256),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER,
  additional_information VARCHAR(4000),
  autoapprove VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS oauth_client_token (
  token_id VARCHAR(256),
  token bytea,
  authentication_id VARCHAR(256) PRIMARY KEY,
  user_name VARCHAR(256),
  client_id VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS oauth_access_token (
  token_id VARCHAR(256),
  token bytea,
  authentication_id VARCHAR(256),
  user_name VARCHAR(256),
  client_id VARCHAR(256),
  authentication bytea,
  refresh_token VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS oauth_refresh_token (
  token_id VARCHAR(256),
  token bytea,
  authentication bytea
);

CREATE TABLE IF NOT EXISTS oauth_code (
  code VARCHAR(256), authentication bytea
);

CREATE TABLE IF NOT EXISTS users (
  id BigInt PRIMARY KEY,
  username VARCHAR(256) NOT NULL,
  password VARCHAR(256) NOT NULL,
  avatar VARCHAR(512),
  first_name VARCHAR(256),
  last_name VARCHAR(256),
  phone VARCHAR(256),
  active boolean,
  enabled boolean
  -- UNIQUE KEY unique_username(username)
);

CREATE TABLE IF NOT EXISTS authorities (
  username VARCHAR(256) NOT NULL,
  authority VARCHAR(256) NOT NULL,
  PRIMARY KEY(username, authority)
);
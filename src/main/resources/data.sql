-- The encrypted client_secret it `secret`
INSERT INTO oauth_client_details (client_id, client_secret, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity)
  VALUES ('clientId', '{bcrypt}$2a$10$vCXMWCn7fDZWOcLnIEhmK.74dvK1Eh8ae2WrWlhr2ETPLoxQctN4.', 'read,write,trust', 'password,authorization_code,refresh_token,client_credentials', 'http://localhost:9001/auth/callback', 'ROLE_CLIENT', 300)
  on conflict do nothing;

-- The encrypted password is `pass`
INSERT INTO users (id, username, password, enabled) 
  VALUES (1, 'user', '{bcrypt}$2a$10$cyf5NfobcruKQ8XGjUJkEegr9ZWFqaea6vjpXWEaSqTa2xL9wjgQC', true),
         (2, 'user2', '{bcrypt}$2a$10$cyf5NfobcruKQ8XGjUJkEegr9ZWFqaea6vjpXWEaSqTa2xL9wjgQC', true),
         (3, 'user3', '{bcrypt}$2a$10$cyf5NfobcruKQ8XGjUJkEegr9ZWFqaea6vjpXWEaSqTa2xL9wjgQC', true)
  on conflict do nothing;

-- INSERT INTO authorities (username, authority) VALUES ('user', 'ROLE_USER');
-- INSERT INTO authorities (username, authority) VALUES ('user2', 'ROLE_USER');
-- INSERT INTO authorities (username, authority) VALUES ('user3', 'ROLE_USER');

CREATE EXTENSION citext;
CREATE EXTENSION pgcrypto;

CREATE DOMAIN email AS citext
CHECK(
   VALUE ~ '^\w+@[a-zA-Z_]+?\.[a-zA-Z]{2,3}$'
);
CREATE DOMAIN web_domain AS TEXT
CHECK (
VALUE ~* '^[a-z0-9]+(\\.[a-z]{2,})$'
);

CREATE TABLE application
(
  version varchar NOT NULL,
  hash    varchar NOT NULL,
  PRIMARY KEY (version)
);

CREATE TABLE client
(
  client_id      serial  NOT NULL,
  client_name    varchar NOT NULL,
  scan_frequency int     NOT NULL,
  last_scheduled date    NOT NULL,
  PRIMARY KEY (client_id)
);

CREATE TABLE client_users
(
  user_id   bigserial NOT NULL,
  client_id serial    NOT NULL,
  PRIMARY KEY (user_id, client_id)
);

CREATE TABLE network
(
  client_id      serial  NOT NULL,
  subnet_id      bigint  NOT NULL,
  subnet_name    varchar NOT NULL,
  subnet_ip      inet    NOT NULL,
  public_facing  bool    NOT NULL,
  subnet_netmask inet    NOT NULL,
  PRIMARY KEY (client_id, subnet_id)
);

CREATE TABLE network_domains
(
  subnet_id bigint     NOT NULL,
  client_id serial     NOT NULL,
  domain    web_domain NOT NULL,
  port      uint2      NOT NULL,
  PRIMARY KEY (domain, port)
);

CREATE TABLE report
(
  report_id   varchar(36) NOT NULL,
  client_id   serial      NOT NULL,
  report_time timestamp   NOT NULL,
  PRIMARY KEY (report_id)
);

CREATE TABLE user
(
  user_id      bigserial   NOT NULL,
  email        email       NOT NULL,
  password     text        NOT NULL,
  client_admin boolean     NOT NULL,
  phone_number varchar(20) NOT NULL,
  PRIMARY KEY (user_id)
);

ALTER TABLE client_users
  ADD CONSTRAINT FK_user_TO_client_users
    FOREIGN KEY (user_id)
    REFERENCES user (user_id);

ALTER TABLE client_users
  ADD CONSTRAINT FK_client_TO_client_users
    FOREIGN KEY (client_id)
    REFERENCES client (client_id);

ALTER TABLE network
  ADD CONSTRAINT FK_client_TO_network
    FOREIGN KEY (client_id)
    REFERENCES client (client_id);

ALTER TABLE network_domains
  ADD CONSTRAINT FK_network_TO_network_domains
    FOREIGN KEY (client_id, subnet_id)
    REFERENCES network (client_id, subnet_id);

ALTER TABLE report
  ADD CONSTRAINT FK_client_TO_report
    FOREIGN KEY (client_id)
    REFERENCES client (client_id);
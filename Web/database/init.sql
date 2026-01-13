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
  client_id      varchar(36) NOT NULL,
  client_name    varchar     NOT NULL,
  scan_frequency int         NOT NULL DEFAULT -1,
  last_scheduled date        NOT NULL DEFAULT '4713-01-01',
  PRIMARY KEY (client_id)
);

CREATE TABLE client_users
(
  user_id   varchar(36) NOT NULL,
  client_id varchar(36) NOT NULL,
  PRIMARY KEY (user_id, client_id)
);

CREATE TABLE network
(
  client_id         varchar(36) NOT NULL,
  subnet_name       varchar     NOT NULL,
  subnet_ip         inet        NOT NULL,
  subnet_netmask    inet        NOT NULL,
  public_facing     bool        NOT NULL,
  verified          bool        NOT NULL DEFAULT FALSE,
  verification_date timestamp  ,
  creation_date     timestamp   DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (client_id, subnet_name)
);

CREATE TABLE network_domains
(
  domain      web_domain  NOT NULL,
  client_id   varchar(36) NOT NULL,
  subnet_name varchar     NOT NULL,
  PRIMARY KEY (domain, client_id, subnet_name)
);

CREATE TABLE report
(
  report_id   varchar(36) NOT NULL,
  client_id   varchar(36) NOT NULL,
  report_time timestamp   NOT NULL,
  PRIMARY KEY (report_id)
);

CREATE TABLE scan_jobs
(
  id            serial       NOT NULL,
  client_id     varchar(36)  NOT NULL,
  subnet_name   varchar      NOT NULL,
  scan_type     varchar(50)  NOT NULL,
  scan_config   text        ,
  status        varchar(20)  DEFAULT 'pending',
  created_at    timestamp   ,
  started_at    timestamp   ,
  completed_at  timestamp   ,
  results       text        ,
  results_path  varchar(500),
  error_message text        ,
  PRIMARY KEY (id)
);

CREATE TABLE users
(
  user_id       varchar(36) NOT NULL,
  email         email       NOT NULL,
  password_hash text        NOT NULL,
  client_admin  boolean     NOT NULL,
  phone_number  varchar(20) NOT NULL,
  created_at    timestamp   DEFAULT CURRENT_TIMESTAMP,
  updated_at    timestamp   DEFAULT CURRENT_TIMESTAMP,
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

ALTER TABLE report
  ADD CONSTRAINT FK_client_TO_report
    FOREIGN KEY (client_id)
    REFERENCES client (client_id);

ALTER TABLE network_domains
  ADD CONSTRAINT FK_network_TO_network_domains
    FOREIGN KEY (client_id, subnet_name)
    REFERENCES network (client_id, subnet_name);

ALTER TABLE scan_jobs
  ADD CONSTRAINT FK_network_TO_scan_jobs
    FOREIGN KEY (client_id, subnet_name)
    REFERENCES network (client_id, subnet_name);

ALTER TABLE scan_jobs
  ADD CONSTRAINT FK_client_TO_scan_jobs
    FOREIGN KEY (client_id)
    REFERENCES client (client_id);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_client_id ON scan_jobs(client_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_at ON scan_jobs(created_at);

-- Done by Austin Finch
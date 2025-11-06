-- Your SQL goes here
CREATE TABLE pod_traffic (
  uuid VARCHAR PRIMARY KEY,
  pod_name VARCHAR,
  pod_namespace VARCHAR,
  pod_ip VARCHAR,
  pod_port VARCHAR,
  ip_protocol VARCHAR,
  traffic_type VARCHAR,
  traffic_in_out_ip VARCHAR,
  traffic_in_out_port VARCHAR,
  decision VARCHAR,
  time_stamp TIMESTAMP NOT NULL
);


-- Your SQL goes here
CREATE TABLE pod_details (
  pod_name VARCHAR PRIMARY KEY,
  pod_ip VARCHAR,
  pod_namespace VARCHAR,
  pod_obj JSON,
  time_stamp TIMESTAMP NOT NULL,
  node_name VARCHAR NOT NULL,
  is_dead BOOLEAN NOT NULL DEFAULT FALSE
);


CREATE TABLE svc_details (
  svc_ip VARCHAR PRIMARY KEY,
  svc_name VARCHAR,
  svc_namespace VARCHAR,
  service_spec JSON,
  time_stamp TIMESTAMP NOT NULL
);


CREATE TABLE pod_syscalls (
  pod_name VARCHAR PRIMARY KEY,
  pod_namespace VARCHAR,
  syscalls VARCHAR,
  arch VARCHAR,
  time_stamp TIMESTAMP NOT NULL
);


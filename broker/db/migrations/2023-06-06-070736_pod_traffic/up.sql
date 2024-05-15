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
  time_stamp TIMESTAMP NOT NULL
);

-- Your SQL goes here
CREATE TABLE pod_details (
  pod_name VARCHAR PRIMARY KEY,
  pod_ip VARCHAR,
  pod_namespace VARCHAR,
  pod_obj JSON,
  time_stamp TIMESTAMP NOT NULL
);


CREATE TABLE svc_details (
  svc_ip VARCHAR PRIMARY KEY,
  svc_name VARCHAR,
  svc_namespace VARCHAR,
  service_spec JSON,
  time_stamp TIMESTAMP NOT NULL
);


-- UUID| POD_NAME | POD_NAMESPACE | POD_IP   |POD_PORT| TRAFFIC_TYPE | TRAFFIC_IN_OUT_IP| TRAFFIC_IN_OUT_PORT|
-- ----|----------|---------------|----------|--------|--------------|------------------|--------------------|
-- xxxx| ngix-123 | web           | 10.2.3.10|  8080  | INGRESS      | 10.3.4.10        | 9090               |
-- xxxx| ngix-123 | web           | 10.2.3.10|  6222  | EGRESS       | 10.3.4.10        | 9090               |



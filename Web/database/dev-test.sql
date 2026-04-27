-- dev testing account
WITH u AS
(
	INSERT INTO users (email, password_hash, client_admin, phone_number, email_verified)
	VALUES ('dev@cyberclinic.com', crypt('dev_pass', gen_salt('bf')), TRUE, '555-0123', TRUE)
	RETURNING user_id
), c AS
(
	INSERT INTO client (client_name, country, province, city)
	VALUES ('Development Client', 'US', 'Nevada', 'Reno')
	RETURNING client_id
)

INSERT INTO client_users (client_id, user_id)
VALUES ((SELECT client_id FROM c), (SELECT user_id FROM u))

INSERT INTO network 
(client_id, subnet_name, subnet_ip, subnet_netmask) VALUES
((SELECT client_id FROM c), 'example_subnet', '<Your_IP_Address>', '<Your_subnet_mask>');
INSERT INTO scan_jobs
()
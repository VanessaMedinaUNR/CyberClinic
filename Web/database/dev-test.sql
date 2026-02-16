-- dev testing account
WITH u AS
(
	INSERT INTO users (email, password_hash, client_admin, phone_number) 
	VALUES ('dev@cyberclinic.com', crypt('dev_pass', gen_salt('bf')), TRUE, '555-0123')
	RETURNING user_id
), c AS
(
	INSERT INTO client (client_name, country, province, city)
	VALUES ('Development Client', 'US', 'Nevada', 'Reno')
	RETURNING client_id
)

INSERT INTO client_users (client_id, user_id)
VALUES ((SELECT client_id FROM c), (SELECT user_id FROM u));
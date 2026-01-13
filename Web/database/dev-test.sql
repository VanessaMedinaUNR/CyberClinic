-- dev testing account
INSERT INTO users (user_id, email, password_hash, client_admin, phone_number) 
VALUES ('99ce94b2-759e-4ed1-a8b0-d76e5366708e', 'dev@cyberclinic.com', crypt('dev_pass', gen_salt('bf')), TRUE, '555-0123');
INSERT INTO client (client_id, client_name)
VALUES ('bfcac88a-c552-4bae-973a-60362a9459ae', 'Development Client');
INSERT INTO client_users (client_id, user_id)
VALUES ('bfcac88a-c552-4bae-973a-60362a9459ae', '99ce94b2-759e-4ed1-a8b0-d76e5366708e');
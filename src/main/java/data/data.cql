-- Create a keyspace
CREATE KEYSPACE IF NOT EXISTS cve_data WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : '1' };

-- Create a table
CREATE TABLE IF NOT EXISTS vulnerabilities (
  cve_id text PRIMARY KEY,
  vulnerabilities list<frozen<vulnerability>>
);

-- Insert some data
INSERT INTO cve_store
(userid, item_count, last_update_timestamp)
VALUES ('9876', 2, toTimeStamp(now()));
INSERT INTO store.shopping_cart
(userid, item_count, last_update_timestamp)
VALUES ('1234', 5, toTimeStamp(now()));
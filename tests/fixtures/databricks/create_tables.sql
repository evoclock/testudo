-- Databricks DDL for the testudo sample fixtures.
--
-- Edit the LOCATION lines below to match where you uploaded the CSVs
-- in step 3 of tests/fixtures/databricks/README.md.
--
-- Unity Catalog volumes:
--   /Volumes/<catalog>/<schema>/testudo_fixtures/sample_employees.csv
-- DBFS:
--   /FileStore/tables/sample_employees.csv

CREATE SCHEMA IF NOT EXISTS testudo;

-- Employees -------------------------------------------------------------------

DROP TABLE IF EXISTS testudo.employees;

CREATE TABLE testudo.employees (
    id         STRING NOT NULL,
    name       STRING NOT NULL,
    email      STRING NOT NULL,
    phone      STRING,
    postcode   STRING,
    department STRING,
    salary     INT,
    hire_date  DATE
)
USING CSV
OPTIONS (header 'true', sep ',')
LOCATION '/Volumes/main/default/testudo_fixtures/sample_employees.csv';

-- Transactions ----------------------------------------------------------------

DROP TABLE IF EXISTS testudo.transactions;

CREATE TABLE testudo.transactions (
    id        STRING NOT NULL,
    amount    DECIMAL(12, 2) NOT NULL,
    iban      STRING,
    card      STRING,
    timestamp TIMESTAMP NOT NULL,
    status    STRING
)
USING CSV
OPTIONS (header 'true', sep ',')
LOCATION '/Volumes/main/default/testudo_fixtures/sample_transactions.csv';

-- Sanity checks ---------------------------------------------------------------

SELECT count(*) AS employee_rows FROM testudo.employees;
SELECT count(*) AS transaction_rows FROM testudo.transactions;

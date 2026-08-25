use anyhow::{Context, Result};
use postgres::types::{FromSqlOwned, ToSql};
use postgres::{Client, NoTls};

pub use postgres::Row;

#[derive(Debug, Clone)]
pub struct PgPool {
    database_url: String,
}

#[derive(Debug, Default)]
pub struct PgPoolOptions {
    max_connections: usize,
}

impl PgPoolOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    pub async fn connect(self, database_url: &str) -> Result<PgPool> {
        let _ = self.max_connections;
        Client::connect(database_url, NoTls)
            .with_context(|| format!("failed to connect to postgres `{database_url}`"))?;
        Ok(PgPool {
            database_url: database_url.to_owned(),
        })
    }
}

pub struct Transaction {
    client: Client,
    complete: bool,
}

impl PgPool {
    fn open_client(&self) -> Result<Client> {
        Client::connect(&self.database_url, NoTls).context("open postgres connection")
    }

    pub async fn begin(&self) -> Result<Transaction> {
        let mut client = self.open_client()?;
        client.batch_execute("BEGIN")?;
        Ok(Transaction {
            client,
            complete: false,
        })
    }
}

impl Transaction {
    pub async fn commit(mut self) -> Result<()> {
        self.client.batch_execute("COMMIT")?;
        self.complete = true;
        Ok(())
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.complete {
            let _ = self.client.batch_execute("ROLLBACK");
        }
    }
}

pub struct Query {
    statement: String,
    parameters: Vec<Box<dyn ToSql + Sync + Send>>,
}

pub fn query(statement: &str) -> Query {
    Query {
        statement: statement.to_owned(),
        parameters: Vec::new(),
    }
}

pub fn query_scalar(statement: &str) -> Query {
    query(statement)
}

pub trait IntoParameter {
    fn into_parameter(self) -> Box<dyn ToSql + Sync + Send>;
}

macro_rules! owned_parameter {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl IntoParameter for $ty {
                fn into_parameter(self) -> Box<dyn ToSql + Sync + Send> {
                    Box::new(self)
                }
            }
        )+
    };
}

owned_parameter!(
    String,
    bool,
    i32,
    i64,
    chrono::DateTime<chrono::Utc>,
    uuid::Uuid,
    serde_json::Value,
    Option<String>,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<serde_json::Value>,
    Option<uuid::Uuid>,
    Vec<String>,
    Vec<uuid::Uuid>,
);

impl IntoParameter for Option<&str> {
    fn into_parameter(self) -> Box<dyn ToSql + Sync + Send> {
        Box::new(self.map(str::to_owned))
    }
}

impl IntoParameter for &str {
    fn into_parameter(self) -> Box<dyn ToSql + Sync + Send> {
        Box::new(self.to_owned())
    }
}

impl IntoParameter for &String {
    fn into_parameter(self) -> Box<dyn ToSql + Sync + Send> {
        Box::new(self.clone())
    }
}

impl IntoParameter for &Option<String> {
    fn into_parameter(self) -> Box<dyn ToSql + Sync + Send> {
        Box::new(self.clone())
    }
}

impl IntoParameter for &uuid::Uuid {
    fn into_parameter(self) -> Box<dyn ToSql + Sync + Send> {
        Box::new(*self)
    }
}

impl IntoParameter for &chrono::DateTime<chrono::Utc> {
    fn into_parameter(self) -> Box<dyn ToSql + Sync + Send> {
        Box::new(*self)
    }
}

impl Query {
    pub fn bind<T: IntoParameter>(mut self, value: T) -> Self {
        self.parameters.push(value.into_parameter());
        self
    }

    pub async fn execute<E: QueryExecutor>(self, executor: E) -> Result<u64> {
        executor.execute(&self.statement, &self.parameters)
    }

    pub async fn fetch_all<E: QueryExecutor>(self, executor: E) -> Result<Vec<Row>> {
        executor.query(&self.statement, &self.parameters)
    }

    pub async fn fetch_one<T: FromSqlOwned, E: QueryExecutor>(self, executor: E) -> Result<T> {
        let row = executor
            .query(&self.statement, &self.parameters)?
            .into_iter()
            .next()
            .context("postgres query returned no rows")?;
        Ok(row.try_get(0)?)
    }
}

pub trait QueryExecutor {
    fn execute(self, statement: &str, parameters: &[Box<dyn ToSql + Sync + Send>]) -> Result<u64>;
    fn query(
        self,
        statement: &str,
        parameters: &[Box<dyn ToSql + Sync + Send>],
    ) -> Result<Vec<Row>>;
}

fn parameter_refs(parameters: &[Box<dyn ToSql + Sync + Send>]) -> Vec<&(dyn ToSql + Sync)> {
    parameters
        .iter()
        .map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync))
        .collect()
}

impl QueryExecutor for &PgPool {
    fn execute(self, statement: &str, parameters: &[Box<dyn ToSql + Sync + Send>]) -> Result<u64> {
        let mut client = self.open_client()?;
        let parameters = parameter_refs(parameters);
        Ok(client.execute(statement, &parameters)?)
    }

    fn query(
        self,
        statement: &str,
        parameters: &[Box<dyn ToSql + Sync + Send>],
    ) -> Result<Vec<Row>> {
        let mut client = self.open_client()?;
        let parameters = parameter_refs(parameters);
        Ok(client.query(statement, &parameters)?)
    }
}

impl QueryExecutor for &mut Transaction {
    fn execute(self, statement: &str, parameters: &[Box<dyn ToSql + Sync + Send>]) -> Result<u64> {
        let parameters = parameter_refs(parameters);
        Ok(self.client.execute(statement, &parameters)?)
    }

    fn query(
        self,
        statement: &str,
        parameters: &[Box<dyn ToSql + Sync + Send>],
    ) -> Result<Vec<Row>> {
        let parameters = parameter_refs(parameters);
        Ok(self.client.query(statement, &parameters)?)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn accepts_unescaped_hash_in_connection_password() {
        let config =
            "postgres://service:pass#word@localhost:5432/servicenet".parse::<postgres::Config>();

        assert!(config.is_ok());
    }
}

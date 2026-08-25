use anyhow::{Context, Result};
use async_trait::async_trait;
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
        let database_url = database_url.to_owned();
        tokio::task::spawn_blocking({
            let database_url = database_url.clone();
            move || Client::connect(&database_url, NoTls)
        })
        .await
        .context("postgres connection task failed")?
        .context("failed to connect to postgres")?;
        Ok(PgPool { database_url })
    }
}

pub struct Transaction {
    client: Option<Client>,
    complete: bool,
}

impl PgPool {
    pub async fn begin(&self) -> Result<Transaction> {
        let database_url = self.database_url.clone();
        let client = tokio::task::spawn_blocking(move || -> Result<Client> {
            let mut client =
                Client::connect(&database_url, NoTls).context("open postgres connection")?;
            client.batch_execute("BEGIN")?;
            Ok(client)
        })
        .await
        .context("postgres transaction task failed")??;
        Ok(Transaction {
            client: Some(client),
            complete: false,
        })
    }
}

impl Transaction {
    pub async fn commit(mut self) -> Result<()> {
        let Some(mut client) = self.client.take() else {
            return Ok(());
        };
        tokio::task::spawn_blocking(move || client.batch_execute("COMMIT"))
            .await
            .context("postgres commit task failed")??;
        self.complete = true;
        Ok(())
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.complete
            && let Some(mut client) = self.client.take()
        {
            let _ = std::thread::Builder::new()
                .name("servicenet-postgres-rollback".to_owned())
                .spawn(move || {
                    let _ = client.batch_execute("ROLLBACK");
                });
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
        executor.execute(self.statement, self.parameters).await
    }

    pub async fn fetch_all<E: QueryExecutor>(self, executor: E) -> Result<Vec<Row>> {
        executor.query(self.statement, self.parameters).await
    }

    pub async fn fetch_one<T: FromSqlOwned, E: QueryExecutor>(self, executor: E) -> Result<T> {
        let row = executor
            .query(self.statement, self.parameters)
            .await?
            .into_iter()
            .next()
            .context("postgres query returned no rows")?;
        Ok(row.try_get(0)?)
    }
}

#[async_trait]
pub trait QueryExecutor {
    async fn execute(
        self,
        statement: String,
        parameters: Vec<Box<dyn ToSql + Sync + Send>>,
    ) -> Result<u64>;
    async fn query(
        self,
        statement: String,
        parameters: Vec<Box<dyn ToSql + Sync + Send>>,
    ) -> Result<Vec<Row>>;
}

fn parameter_refs(parameters: &[Box<dyn ToSql + Sync + Send>]) -> Vec<&(dyn ToSql + Sync)> {
    parameters
        .iter()
        .map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync))
        .collect()
}

#[async_trait]
impl QueryExecutor for &PgPool {
    async fn execute(
        self,
        statement: String,
        parameters: Vec<Box<dyn ToSql + Sync + Send>>,
    ) -> Result<u64> {
        let database_url = self.database_url.clone();
        tokio::task::spawn_blocking(move || -> Result<u64> {
            let mut client =
                Client::connect(&database_url, NoTls).context("open postgres connection")?;
            let parameters = parameter_refs(&parameters);
            Ok(client.execute(&statement, &parameters)?)
        })
        .await
        .context("postgres query task failed")?
    }

    async fn query(
        self,
        statement: String,
        parameters: Vec<Box<dyn ToSql + Sync + Send>>,
    ) -> Result<Vec<Row>> {
        let database_url = self.database_url.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<Row>> {
            let mut client =
                Client::connect(&database_url, NoTls).context("open postgres connection")?;
            let parameters = parameter_refs(&parameters);
            Ok(client.query(&statement, &parameters)?)
        })
        .await
        .context("postgres query task failed")?
    }
}

#[async_trait]
impl QueryExecutor for &mut Transaction {
    async fn execute(
        self,
        statement: String,
        parameters: Vec<Box<dyn ToSql + Sync + Send>>,
    ) -> Result<u64> {
        let mut client = self
            .client
            .take()
            .context("postgres transaction client is unavailable")?;
        let result = tokio::task::spawn_blocking(move || -> Result<(Client, u64)> {
            let parameters = parameter_refs(&parameters);
            let result = client
                .execute(&statement, &parameters)
                .map_err(anyhow::Error::from);
            Ok((client, result?))
        })
        .await
        .context("postgres transaction query task failed")??;
        self.client = Some(result.0);
        Ok(result.1)
    }

    async fn query(
        self,
        statement: String,
        parameters: Vec<Box<dyn ToSql + Sync + Send>>,
    ) -> Result<Vec<Row>> {
        let mut client = self
            .client
            .take()
            .context("postgres transaction client is unavailable")?;
        let result = tokio::task::spawn_blocking(move || -> Result<(Client, Vec<Row>)> {
            let parameters = parameter_refs(&parameters);
            let result = client
                .query(&statement, &parameters)
                .map_err(anyhow::Error::from);
            Ok((client, result?))
        })
        .await
        .context("postgres transaction query task failed")??;
        self.client = Some(result.0);
        Ok(result.1)
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

    #[tokio::test]
    async fn connection_failure_is_returned_without_nested_runtime_panic() {
        let result = super::PgPoolOptions::new()
            .connect("postgres://service:password@127.0.0.1:1/servicenet")
            .await;

        assert!(result.is_err());
    }
}

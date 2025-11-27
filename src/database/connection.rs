//! Database connection management and core functionality.

#![allow(dead_code)]

use crate::errors::AppResult;
use rusqlite::Connection;
use tracing::info;

/// Core database connection wrapper with shared functionality
pub struct DatabaseConnection {
    connection: Connection,
}

impl DatabaseConnection {
    /// Create a new database connection
    pub fn new(database_path: &str) -> AppResult<Self> {
        let connection = Connection::open(database_path)?;

        let db_conn = Self { connection };
        info!("Database connection established: {}", database_path);
        Ok(db_conn)
    }

    /// Get a reference to the underlying connection
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Execute a function within a database transaction
    pub fn execute_transaction<F, R>(&mut self, f: F) -> AppResult<R>
    where
        F: FnOnce(&rusqlite::Transaction) -> AppResult<R>,
    {
        let tx = self.connection.transaction()?;

        let result = f(&tx)?;

        tx.commit()?;

        Ok(result)
    }
}

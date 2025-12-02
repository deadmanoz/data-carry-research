use corepc_client::bitcoin::Transaction;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::debug;

/// Thread-safe transaction cache for avoiding duplicate RPC calls
#[derive(Clone)]
pub struct TransactionCache {
    cache: Arc<Mutex<HashMap<String, Transaction>>>,
    hits: Arc<Mutex<u64>>,
    misses: Arc<Mutex<u64>>,
}

impl TransactionCache {
    /// Create a new empty transaction cache
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            hits: Arc::new(Mutex::new(0)),
            misses: Arc::new(Mutex::new(0)),
        }
    }

    /// Get a transaction from cache if it exists
    pub fn get(&self, txid: &str) -> Option<Transaction> {
        let cache = self.cache.lock().unwrap();
        match cache.get(txid) {
            Some(transaction) => {
                *self.hits.lock().unwrap() += 1;
                debug!("Cache hit for transaction: {}", txid);
                Some(transaction.clone())
            }
            None => {
                *self.misses.lock().unwrap() += 1;
                debug!("Cache miss for transaction: {}", txid);
                None
            }
        }
    }

    /// Store a transaction in the cache
    pub fn put(&self, txid: String, transaction: Transaction) {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(txid.clone(), transaction);
        debug!("Cached transaction: {}", txid);
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> CacheStats {
        let hits = *self.hits.lock().unwrap();
        let misses = *self.misses.lock().unwrap();
        CacheStats { hits, misses }
    }

}

#[cfg(test)]
impl TransactionCache {
    /// Clear the cache (test-only)
    pub fn clear(&self) {
        use tracing::info;
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
        *self.hits.lock().unwrap() = 0;
        *self.misses.lock().unwrap() = 0;
        info!("Transaction cache cleared");
    }

    /// Get the current cache size (test-only)
    pub fn size(&self) -> usize {
        let cache = self.cache.lock().unwrap();
        cache.len()
    }
}

impl Default for TransactionCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache performance statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
}

impl CacheStats {
    /// Calculate the cache hit rate as a percentage
    pub fn hit_rate(&self) -> f64 {
        if self.hits + self.misses == 0 {
            0.0
        } else {
            (self.hits as f64 / (self.hits + self.misses) as f64) * 100.0
        }
    }

    /// Get total cache requests
    pub fn total_requests(&self) -> u64 {
        self.hits + self.misses
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corepc_client::bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
    use std::str::FromStr;

    fn create_dummy_transaction(txid_str: &str) -> Transaction {
        let txid = Txid::from_str(txid_str).unwrap();
        let outpoint = OutPoint { txid, vout: 0 };

        Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn test_cache_basic_operations() {
        let cache = TransactionCache::new();
        let txid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let transaction = create_dummy_transaction(txid);

        // Test miss
        assert!(cache.get(txid).is_none());

        // Test put and hit
        cache.put(txid.to_string(), transaction.clone());
        assert!(cache.get(txid).is_some());

        // Test stats
        let stats = cache.get_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_rate(), 50.0);
    }

    #[test]
    fn test_cache_stats() {
        let cache = TransactionCache::new();
        let txid1 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let txid2 = "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let transaction1 = create_dummy_transaction(txid1);
        let transaction2 = create_dummy_transaction(txid2);

        // Cache two transactions
        cache.put(txid1.to_string(), transaction1);
        cache.put(txid2.to_string(), transaction2);

        // Hit both transactions multiple times
        cache.get(txid1);
        cache.get(txid1);
        cache.get(txid2);

        // Miss on a third transaction
        cache.get("nonexistent");

        let stats = cache.get_stats();
        assert_eq!(stats.hits, 3);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_rate(), 75.0);
        assert_eq!(stats.total_requests(), 4);
    }

    #[test]
    fn test_cache_clear() {
        let cache = TransactionCache::new();
        let txid = "3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let transaction = create_dummy_transaction(txid);

        cache.put(txid.to_string(), transaction);
        cache.get(txid);

        assert_eq!(cache.size(), 1);
        assert_eq!(cache.get_stats().hits, 1);

        cache.clear();

        assert_eq!(cache.size(), 0);
        assert_eq!(cache.get_stats().hits, 0);
        assert_eq!(cache.get_stats().misses, 0);
    }
}

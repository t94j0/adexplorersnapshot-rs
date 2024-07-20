use super::Caches;
use super::Object;
use super::Snapshot;
use crate::parser::cache::Cache;
use crate::sid::SID;
use serde::Serialize;
use std::io::Result;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct ADExplorerSnapshot {
    pub snapshot: Snapshot,
    #[serde(skip_serializing)]
    pub caches: Caches,
}

impl ADExplorerSnapshot {
    pub fn snapshot_from_file<P: AsRef<Path>>(path: P) -> Result<ADExplorerSnapshot> {
        let snapshot = Snapshot::snapshot_from_file(path)?;
        let mut caches = Caches::new();
        caches.build_caches(&snapshot);

        Ok(ADExplorerSnapshot { snapshot, caches })
    }

    pub fn snapshot_from_memory(snapshot: impl AsRef<[u8]>) -> Result<ADExplorerSnapshot> {
        let snapshot = Snapshot::snapshot_from_memory(snapshot)?;
        let mut caches = Caches::new();
        caches.build_caches(&snapshot);

        Ok(ADExplorerSnapshot { snapshot, caches })
    }

    pub fn build_caches(&mut self, caches: Caches) {
        self.caches = caches;
    }

    pub fn get_root_domain(&self) -> Option<&Object> {
        let root_domain_dn = self.caches.root_domain.as_ref()?;
        let root_domain_index = self.caches.dn_cache.get(root_domain_dn)?;
        self.snapshot.objects.get(*root_domain_index)
    }

    pub fn get_sid(&self, sid: &SID) -> Option<&Object> {
        let sid_index = self.caches.sid_cache.get(sid)?;
        self.snapshot.objects.get(*sid_index)
    }

    pub fn get_computer(&self, computer: &str) -> Option<&Object> {
        let computer_index = self.caches.computer_cache.get(&computer.to_string())?;
        self.snapshot.objects.get(*computer_index)
    }

    pub fn get_dn(&self, dn: &str) -> Option<&Object> {
        let dn_index = self.caches.dn_cache.get(&dn.to_string())?;
        self.snapshot.objects.get(*dn_index)
    }
}

// Copyright 2024 ADM
// Copyright 2021-2023 Protocol Labs
// SPDX-License-Identifier: Apache-2.0, MIT

use cid::Cid;
use fil_actors_runtime::{runtime::Runtime, ActorError, Map2, DEFAULT_HAMT_CONFIG};
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::tuple::*;
use fvm_shared::{address::Address, ActorID};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type MachineCodes<BS> = Map2<BS, Vec<u8>, Cid>;
pub type DeployerMap<BS> = Map2<BS, Address, ()>;
pub type OwnerMap<BS> = Map2<BS, ActorID, Vec<Address>>;

/// The args used to create the permission mode in storage
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PermissionModeParams {
    /// No restriction, everyone can deploy
    Unrestricted,
    /// Only whitelisted addresses can deploy
    AllowList(Vec<Address>),
}

/// The permission mode for controlling who can deploy contracts
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PermissionMode {
    /// No restriction, everyone can deploy
    Unrestricted,
    /// Only whitelisted addresses can deploy
    AllowList(Cid), // HAMT[Address]()
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct State {
    pub machines: Cid, // HAMT[u64]Cid
    pub permission_mode: PermissionMode,
    pub owners: Cid, // HAMT[ActorID]Vec<Address>
}

impl State {
    pub fn new<BS: Blockstore>(
        store: &BS,
        machine_codes: HashMap<String, Cid>,
        permission_mode: PermissionModeParams,
    ) -> Result<State, ActorError> {
        let mut machine_map = MachineCodes::empty(store, DEFAULT_HAMT_CONFIG, "machines");
        for (name, code) in machine_codes {
            machine_map.set(&name.into_bytes(), code)?;
        }
        let machines = machine_map.flush()?;

        let permission_mode = match permission_mode {
            PermissionModeParams::Unrestricted => PermissionMode::Unrestricted,
            PermissionModeParams::AllowList(deployers) => {
                let mut deployers_map = DeployerMap::empty(store, DEFAULT_HAMT_CONFIG, "deployers");
                for d in deployers {
                    deployers_map.set(&d, ())?;
                }
                PermissionMode::AllowList(deployers_map.flush()?)
            }
        };

        let owners = OwnerMap::empty(store, DEFAULT_HAMT_CONFIG, "owners").flush()?;

        Ok(State { machines, permission_mode, owners })
    }

    pub fn get_machine_code<BS: Blockstore>(
        &self,
        store: &BS,
        name: String,
    ) -> Result<Option<Cid>, ActorError> {
        let machine_map =
            MachineCodes::load(store, &self.machines, DEFAULT_HAMT_CONFIG, "machines")?;
        let code = machine_map.get(&name.into_bytes()).map(|c| c.cloned())?;
        Ok(code)
    }

    pub fn set_deployers<BS: Blockstore>(
        &mut self,
        store: &BS,
        deployers: Vec<Address>,
    ) -> anyhow::Result<()> {
        match self.permission_mode {
            PermissionMode::Unrestricted => {
                return Err(anyhow::anyhow!(
                    "cannot set deployers in unrestricted permission mode"
                ));
            }
            PermissionMode::AllowList(_) => {
                let mut deployers_map = DeployerMap::empty(store, DEFAULT_HAMT_CONFIG, "deployers");
                for d in deployers {
                    deployers_map.set(&d, ())?;
                }
                self.permission_mode = PermissionMode::AllowList(deployers_map.flush()?);
            }
        }
        Ok(())
    }

    pub fn can_deploy(&self, rt: &impl Runtime, deployer: ActorID) -> Result<bool, ActorError> {
        Ok(match &self.permission_mode {
            PermissionMode::Unrestricted => true,
            PermissionMode::AllowList(cid) => {
                let deployers =
                    DeployerMap::load(rt.store(), cid, DEFAULT_HAMT_CONFIG, "deployers")?;
                let mut allowed = false;
                deployers.for_each(|k, _| {
                    // Normalize allowed addresses to ID addresses, so we can compare any kind of allowlisted address.
                    // This includes f1, f2, f3, etc.
                    // We cannot normalize the allowlist at construction time because the addresses may not be bound to IDs yet (counterfactual usage).
                    // Unfortunately, API of Hamt::for_each won't let us stop iterating on match, so this is more wasteful than we'd like. We can optimize later.
                    // Hamt has implemented Iterator recently, but it's not exposed through Map2 (see ENG-800).
                    allowed = allowed || rt.resolve_address(&k) == Some(deployer);
                    Ok(())
                })?;
                allowed
            }
        })
    }

    pub fn list_by_owner<BS: Blockstore>(
        &self,
        store: &BS,
        owner: ActorID,
    ) -> anyhow::Result<Vec<Address>> {
        let owners = OwnerMap::load(store, &self.owners, DEFAULT_HAMT_CONFIG, "owners")?;
        let machines = owners.get(&owner)?.map(|machines| machines.to_owned()).unwrap_or_default();
        Ok(machines)
    }

    pub fn set_owner<BS: Blockstore>(
        &mut self,
        store: &BS,
        machine: Address,
        owner: ActorID,
    ) -> anyhow::Result<()> {
        let mut owners = OwnerMap::load(store, &self.owners, DEFAULT_HAMT_CONFIG, "owners")?;
        let mut machines =
            owners.get(&owner)?.map(|machines| machines.to_owned()).unwrap_or_default();
        machines.push(machine);
        owners.set(&owner, machines)?;
        self.owners = owners.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cid::Cid;

    use crate::state::PermissionMode;

    #[test]
    fn test_serialization() {
        let p = PermissionMode::Unrestricted;
        let v = fvm_ipld_encoding::to_vec(&p).unwrap();

        let dp: PermissionMode = fvm_ipld_encoding::from_slice(&v).unwrap();
        assert_eq!(dp, p);

        let p = PermissionMode::AllowList(Cid::default());
        let v = fvm_ipld_encoding::to_vec(&p).unwrap();

        let dp: PermissionMode = fvm_ipld_encoding::from_slice(&v).unwrap();
        assert_eq!(dp, p)
    }
}

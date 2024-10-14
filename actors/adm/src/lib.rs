// Copyright 2024 ADM Contributors
// Copyright 2022-2024 Protocol Labs
// SPDX-License-Identifier: Apache-2.0, MIT

use std::collections::HashMap;
use std::iter;

use cid::Cid;
use ext::account::PUBKEY_ADDRESS_METHOD;
use ext::init::{ExecParams, ExecReturn};
use ext::machine::WriteAccess;
use fil_actors_runtime::{
    actor_dispatch_unrestricted, actor_error, deserialize_block, extract_send_result,
    runtime::{builtins::Type, ActorCode, Runtime},
    ActorDowncast, ActorError, AsActorError, ADM_ACTOR_ID, INIT_ACTOR_ADDR, SYSTEM_ACTOR_ADDR,
};
use fvm_ipld_encoding::{ipld_block::IpldBlock, tuple::*, RawBytes};
use fvm_shared::address::Payload;
use fvm_shared::sys::SendFlags;
use fvm_shared::{address::Address, error::ExitCode, ActorID, METHOD_CONSTRUCTOR};
use num_derive::FromPrimitive;
use num_traits::Zero;

use crate::state::PermissionMode;
pub use crate::state::{Kind, Metadata, PermissionModeParams, State};

pub mod ext;
mod state;

#[cfg(feature = "fil-actor")]
fil_actors_runtime::wasm_trampoline!(AdmActor);

#[derive(FromPrimitive)]
#[repr(u64)]
pub enum Method {
    Constructor = METHOD_CONSTRUCTOR,
    // Exported calls (computed via `frc42_dispatch::method_hash!` & hardcoded to avoid dependency issues)
    CreateExternal = 1214262202,
    UpdateDeployers = 1768606754,
    ListMetadata = 2283215593,
}

#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct ConstructorParams {
    pub machine_codes: HashMap<Kind, Cid>,
    pub permission_mode: PermissionModeParams,
}

#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct CreateExternalParams {
    pub owner: Address,
    pub kind: Kind,
    pub write_access: WriteAccess,
    pub metadata: HashMap<String, String>,
}

#[derive(Serialize_tuple, Deserialize_tuple, Debug, PartialEq, Eq)]
pub struct CreateExternalReturn {
    pub actor_id: ActorID,
    pub robust_address: Option<Address>,
}

#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct ListMetadataParams {
    pub owner: Address,
}

fn create_machine(
    rt: &impl Runtime,
    owner: Address,
    write_access: WriteAccess,
    code_cid: Cid,
    metadata: HashMap<String, String>,
) -> Result<CreateExternalReturn, ActorError> {
    let constructor_params =
        RawBytes::serialize(ext::machine::ConstructorParams { owner, write_access, metadata })?;
    let ret: ExecReturn = deserialize_block(extract_send_result(rt.send_simple(
        &INIT_ACTOR_ADDR,
        ext::init::EXEC_METHOD,
        IpldBlock::serialize_cbor(&ExecParams { code_cid, constructor_params })?,
        rt.message().value_received(),
    ))?)?;

    // Initialize the machine with its robust address
    extract_send_result(rt.send_simple(
        &ret.id_address,
        ext::machine::INIT_METHOD,
        IpldBlock::serialize_cbor(&ext::machine::InitParams {
            robust_address: ret.robust_address,
        })?,
        rt.message().value_received(),
    ))?;

    Ok(CreateExternalReturn {
        actor_id: ret.id_address.id().unwrap(),
        robust_address: Some(ret.robust_address),
    })
}

fn ensure_deployer_allowed(rt: &impl Runtime) -> Result<(), ActorError> {
    // The caller is guaranteed to be an ID address.
    let caller_id = rt.message().caller().id().unwrap();

    // Check if the caller is a contract. If it is, and we're in permissioned mode,
    // then the contract was either there in genesis or has been deployed by a whitelisted
    // account; in both cases it's been known up front whether it creates other contracts,
    // and if that was undesireable it would not have been deployed as it is.
    let code_cid = rt.get_actor_code_cid(&caller_id).expect("caller has code");
    if rt.resolve_builtin_actor_type(&code_cid) == Some(Type::EVM) {
        return Ok(());
    }

    // Check if the caller is whitelisted.
    let state: State = rt.state()?;
    if !state.can_deploy(rt, caller_id)? {
        return Err(ActorError::forbidden(String::from("sender not allowed to deploy contracts")));
    }

    Ok(())
}

fn resolve_external(rt: &impl Runtime, address: Address) -> Result<Address, ActorError> {
    let actor_id = if let Ok(id) = address.id() {
        id
    } else {
        return Ok(address);
    };
    let code_cid = rt.get_actor_code_cid(&actor_id).expect("failed to lookup caller code");
    match rt.resolve_builtin_actor_type(&code_cid) {
        Some(Type::Account) => {
            let result = rt
                .send(
                    &address,
                    PUBKEY_ADDRESS_METHOD,
                    None,
                    Zero::zero(),
                    None,
                    SendFlags::READ_ONLY,
                )
                .context_code(
                    ExitCode::USR_ASSERTION_FAILED,
                    "account failed to return its key address",
                )?;
            if !result.exit_code.is_success() {
                return Err(ActorError::checked(
                    result.exit_code,
                    "failed to retrieve account robust address".to_string(),
                    None,
                ));
            }
            let robust_addr: Address = deserialize_block(result.return_data)?;
            Ok(robust_addr)
        }
        Some(Type::EthAccount) | Some(Type::EVM) => rt.lookup_delegated_address(actor_id).ok_or(
            ActorError::forbidden(format!("actor {} does not have delegated address", actor_id)),
        ),
        Some(t) => Err(ActorError::forbidden(format!("disallowed caller type {}", t.name()))),
        None => Err(ActorError::forbidden(format!("disallowed caller code {code_cid}"))),
    }
}

fn get_machine_code(rt: &impl Runtime, kind: &Kind) -> Result<Cid, ActorError> {
    rt.state::<State>()?
        .get_machine_code(rt.store(), kind)?
        .ok_or(ActorError::not_found(format!("machine code for kind '{}' not found", kind)))
}

pub struct AdmActor;

impl AdmActor {
    pub fn constructor(rt: &impl Runtime, args: ConstructorParams) -> Result<(), ActorError> {
        let actor_id = rt.resolve_address(&rt.message().receiver()).unwrap();
        if actor_id != ADM_ACTOR_ID {
            return Err(ActorError::forbidden(format!(
                "The ADM must be deployed at {ADM_ACTOR_ID}, was deployed at {actor_id}"
            )));
        }
        rt.validate_immediate_caller_is(iter::once(&SYSTEM_ACTOR_ADDR))?;

        let st = State::new(rt.store(), args.machine_codes, args.permission_mode)?;
        rt.create(&st)
    }

    fn update_deployers(rt: &impl Runtime, deployers: Vec<Address>) -> Result<(), ActorError> {
        rt.validate_immediate_caller_accept_any()?;

        // Reject update if we're unrestricted.
        let state: State = rt.state()?;
        if !matches!(state.permission_mode, PermissionMode::AllowList(_)) {
            return Err(ActorError::forbidden(String::from(
                "deployers can only be updated in allowlist mode",
            )));
        };

        // Check that the caller is in the allowlist.
        let caller_id = rt.message().caller().id().unwrap();
        if !state.can_deploy(rt, caller_id)? {
            return Err(ActorError::forbidden(String::from(
                "sender not allowed to update deployers",
            )));
        }

        // Perform the update.
        rt.transaction(|st: &mut State, rt| {
            st.set_deployers(rt.store(), deployers).map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_ARGUMENT, "failed to set deployers")
            })
        })?;

        Ok(())
    }

    /// Create a new machine from off-chain.
    /// TODO: we'll want to revert this change (via `5f19742`) once we enable machine delegated
    /// addresses, and also handle `create`-related methods similar to the EAM.
    /// See here for context: https://github.com/hokunet/ipc/pull/252#issuecomment-2408701031
    pub fn create_external(
        rt: &impl Runtime,
        params: CreateExternalParams,
    ) -> Result<CreateExternalReturn, ActorError> {
        ensure_deployer_allowed(rt)?;
        rt.validate_immediate_caller_accept_any()?;

        let owner = resolve_external(rt, params.owner)?;
        let machine_code = get_machine_code(rt, &params.kind)?;
        let ret =
            create_machine(rt, owner, params.write_access, machine_code, params.metadata.clone())?;

        // Save machine metadata.
        let address = ret.robust_address.expect("rubust address");
        rt.transaction(|st: &mut State, rt| {
            st.set_metadata(rt.store(), owner, address, params.kind, params.metadata).map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_ARGUMENT, "failed to set machine metadata")
            })
        })?;

        Ok(ret)
    }

    /// Returns a list of machine metadata by owner.
    ///
    /// Metadata includes machine kind and address.
    pub fn list_metadata(
        rt: &impl Runtime,
        params: ListMetadataParams,
    ) -> Result<Vec<Metadata>, ActorError> {
        rt.validate_immediate_caller_accept_any()?;

        if let &Payload::ID(_) = params.owner.payload() {
            return Err(ActorError::illegal_argument(String::from("robust address required")));
        }

        let st: State = rt.state()?;
        let metadata = st.get_metadata(rt.store(), params.owner).map_err(|e| {
            e.downcast_default(ExitCode::USR_ILLEGAL_ARGUMENT, "failed to get metadata")
        })?;
        Ok(metadata)
    }
}

impl ActorCode for AdmActor {
    type Methods = Method;

    fn name() -> &'static str {
        "ADMAddressManager"
    }

    actor_dispatch_unrestricted! {
        Constructor => constructor,
        CreateExternal => create_external,
        UpdateDeployers => update_deployers,
        ListMetadata => list_metadata,
    }
}

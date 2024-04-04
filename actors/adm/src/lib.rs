// Copyright 2024 ADM

use std::collections::HashMap;
use std::iter;

use cid::Cid;
use fvm_ipld_encoding::{ipld_block::IpldBlock, tuple::*, RawBytes};
use fvm_shared::{address::Address, error::ExitCode, ActorID, METHOD_CONSTRUCTOR};
use num_derive::FromPrimitive;

use ext::init::{ExecParams, ExecReturn};
use fil_actors_runtime::{
    actor_dispatch_unrestricted, actor_error, deserialize_block, extract_send_result,
    runtime::{builtins::Type, ActorCode, Runtime},
    ActorDowncast, ActorError, ADM_ACTOR_ID, INIT_ACTOR_ADDR, SYSTEM_ACTOR_ADDR,
};

use crate::state::PermissionMode;
pub use crate::state::{PermissionModeParams, State};

pub mod ext;
mod state;

#[cfg(feature = "fil-actor")]
fil_actors_runtime::wasm_trampoline!(AdmActor);

#[derive(FromPrimitive)]
#[repr(u64)]
pub enum Method {
    Constructor = METHOD_CONSTRUCTOR,
    CreateExternal = 2,
    UpdateDeployers = 3,
    ListByOwner = 4,
}

#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct CreateExternalParams {
    pub machine_name: String,
}

#[derive(Serialize_tuple, Deserialize_tuple, Debug, PartialEq, Eq)]
pub struct CreateExternalReturn {
    pub actor_id: ActorID,
    pub robust_address: Option<Address>,
}

#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct ListByOwnerParams {
    pub owner: Address,
}

#[derive(Serialize_tuple, Deserialize_tuple, Debug, PartialEq, Eq)]
pub struct ListByOwnerReturn {
    pub machines: Vec<Address>,
}

fn create_machine(
    rt: &impl Runtime,
    creator: ActorID,
    code_cid: Cid,
) -> Result<CreateExternalReturn, ActorError> {
    let constructor_params = RawBytes::serialize(ext::machine::ConstructorParams { creator })?;
    let value = rt.message().value_received();

    let init_params = ExecParams { code_cid, constructor_params };

    let ret: ExecReturn = deserialize_block(extract_send_result(rt.send_simple(
        &INIT_ACTOR_ADDR,
        ext::init::EXEC_METHOD,
        IpldBlock::serialize_cbor(&init_params)?,
        value,
    ))?)?;

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

fn resolve_caller_external(rt: &impl Runtime) -> Result<ActorID, ActorError> {
    let caller = rt.message().caller();
    let caller_id = caller.id().unwrap();
    let caller_code_cid = rt.get_actor_code_cid(&caller_id).expect("failed to lookup caller code");
    match rt.resolve_builtin_actor_type(&caller_code_cid) {
        Some(Type::Account) | Some(Type::EthAccount) => Ok(caller_id),
        Some(t) => Err(ActorError::forbidden(format!("disallowed caller type {}", t.name()))),
        None => Err(ActorError::forbidden(format!("disallowed caller code {caller_code_cid}"))),
    }
}

fn get_machine_code(rt: &impl Runtime, name: String) -> Result<Cid, ActorError> {
    let st: State = rt.state()?;
    match st.get_machine_code(rt.store(), name.clone())? {
        Some(code) => Ok(code),
        None => Err(ActorError::not_found(format!("machine code for name '{}' not found", name))),
    }
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
    ///
    /// Permissions: May be called by builtin or eth accounts.
    pub fn create_external(
        rt: &impl Runtime,
        params: CreateExternalParams,
    ) -> Result<CreateExternalReturn, ActorError> {
        ensure_deployer_allowed(rt)?;

        // We only accept calls by top-level accounts.
        // `resolve_caller_external` will check the actual types.
        rt.validate_immediate_caller_is(&[rt.message().origin()])?;

        let creator = resolve_caller_external(rt)?;
        let machine_code = get_machine_code(rt, params.machine_name)?;
        let ret = create_machine(rt, creator, machine_code)?;

        // Save machine metadata.
        // Currently, this is just owner info, but could be extended in the future.
        rt.transaction(|st: &mut State, rt| {
            st.set_owner(rt.store(), ret.robust_address.unwrap(), creator).map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_ARGUMENT, "failed to set machine metadata")
            })
        })?;

        Ok(ret)
    }

    /// List machines by owner.
    pub fn list_by_owner(
        rt: &impl Runtime,
        params: ListByOwnerParams,
    ) -> Result<ListByOwnerReturn, ActorError> {
        rt.validate_immediate_caller_accept_any()?;

        if let Some(owner) = rt.resolve_address(&params.owner) {
            let machines = rt.transaction(|st: &mut State, rt| {
                st.list_by_owner(rt.store(), owner).map_err(|e| {
                    e.downcast_default(ExitCode::USR_ILLEGAL_ARGUMENT, "failed to list by owner")
                })
            })?;
            Ok(ListByOwnerReturn { machines })
        } else {
            Err(ActorError::not_found(String::from("owner does not exist")))
        }
    }
}

#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct ConstructorParams {
    machine_codes: HashMap<String, Cid>,
    permission_mode: PermissionModeParams,
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
        ListByOwner => list_by_owner,
    }
}

// #[cfg(test)]
// mod test {
//     use fil_actors_runtime::test_utils::MockRuntime;
//     use fvm_shared::error::ExitCode;
//
//     use crate::compute_address_create2;
//
//     use super::{compute_address_create, create_actor, EthAddress};
//
//     #[test]
//     fn test_create_actor_rejects() {
//         let rt = MockRuntime::default();
//         let creator = EthAddress::from_id(1);
//
//         // Reject ID.
//         let new_addr = EthAddress::from_id(8224);
//         assert_eq!(
//             ExitCode::USR_FORBIDDEN,
//             create_actor(&rt, creator, new_addr, Vec::new()).unwrap_err().exit_code()
//         );
//
//         // Reject EVM Precompile.
//         let mut new_addr = EthAddress::null();
//         new_addr.0[19] = 0x20;
//         assert_eq!(
//             ExitCode::USR_FORBIDDEN,
//             create_actor(&rt, creator, new_addr, Vec::new()).unwrap_err().exit_code()
//         );
//
//         // Reject Native Precompile.
//         new_addr.0[0] = 0xfe;
//         assert_eq!(
//             ExitCode::USR_FORBIDDEN,
//             create_actor(&rt, creator, new_addr, Vec::new()).unwrap_err().exit_code()
//         );
//
//         // Reject Null.
//         let new_addr = EthAddress::null();
//         assert_eq!(
//             ExitCode::USR_FORBIDDEN,
//             create_actor(&rt, creator, new_addr, Vec::new()).unwrap_err().exit_code()
//         );
//     }
//
//     #[test]
//     fn test_create_address() {
//         let rt = MockRuntime::default();
//         // check addresses against externally generated cases
//         for (from, nonce, expected) in &[
//             ([0u8; 20], 0u64, hex_literal::hex!("bd770416a3345f91e4b34576cb804a576fa48eb1")),
//             ([0; 20], 200, hex_literal::hex!("a6b14387c1356b443061155e9c3e17f72c1777e5")),
//             ([123; 20], 12345, hex_literal::hex!("809a9ab0471e78ee5100e96ca4d0828d1b97e2ba")),
//         ] {
//             let result = compute_address_create(&rt, &EthAddress(*from), *nonce);
//             assert_eq!(result.0[..], expected[..]);
//         }
//     }
//
//     #[test]
//     fn test_create_address2() {
//         let rt = MockRuntime::default();
//         // check addresses against externally generated cases
//         for (from, salt, initcode, expected) in &[
//             (
//                 [0u8; 20],
//                 [0u8; 32],
//                 &b""[..],
//                 hex_literal::hex!("e33c0c7f7df4809055c3eba6c09cfe4baf1bd9e0"),
//             ),
//             (
//                 [0x99u8; 20],
//                 [0x42; 32],
//                 &b"foobar"[..],
//                 hex_literal::hex!("64425c93a90901271fa355c2bc462190803b97d4"),
//             ),
//         ] {
//             let result = compute_address_create2(&rt, &EthAddress(*from), salt, initcode);
//             assert_eq!(result.0[..], expected[..]);
//         }
//     }
// }

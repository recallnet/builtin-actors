use fvm_ipld_encoding::tuple::*;
use serde::{Deserialize, Serialize};

pub mod init {
    use super::*;
    use cid::Cid;
    use fvm_ipld_encoding::RawBytes;
    use fvm_shared::address::Address;

    pub const EXEC_METHOD: u64 = 2;

    /// Init actor Exec Params
    #[derive(Serialize_tuple, Deserialize_tuple)]
    pub struct ExecParams {
        pub code_cid: Cid,
        pub constructor_params: RawBytes,
    }

    /// Init actor Exec Return value
    #[derive(Debug, Serialize_tuple, Deserialize_tuple)]
    pub struct ExecReturn {
        /// ID based address for created actor
        pub id_address: Address,
        /// Reorg safe address for actor
        pub robust_address: Address,
    }
}

pub mod account {
    pub const PUBKEY_ADDRESS_METHOD: u64 = 2;
}

pub mod machine {
    use super::*;
    use fvm_shared::ActorID;

    #[derive(Debug, Serialize_tuple, Deserialize_tuple)]
    pub struct ConstructorParams {
        /// The machine creator.
        pub creator: ActorID,
        /// Write access dictates who can write to the machine.
        pub write_access: WriteAccess,
    }

    /// The different types of machine write access.
    #[derive(Debug, Serialize, Deserialize)]
    pub enum WriteAccess {
        /// Only the owner can write to the machine.
        OnlyOwner,
        /// Any valid account can write to the machine.
        Public,
    }
}

//! Instruction handlers for x0-registry

pub mod register_agent;
pub mod update_registry;
pub mod deactivate_entry;
pub mod reactivate_entry;
pub mod deregister_agent;

pub use register_agent::*;
pub use update_registry::*;
pub use deactivate_entry::*;
pub use reactivate_entry::*;
pub use deregister_agent::*;

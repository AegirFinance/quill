use anyhow::anyhow;
use ic_agent::{
    export::Principal,
    Agent, Identity, Signature,
};
use candid::{Encode, Decode, CandidType};
use serde::{Deserialize, de::DeserializeOwned, Serialize};
use garcon::TimeoutWaiter;
use tokio::runtime::Handle;
use crossbeam::channel;
use std::convert::TryInto;
use std::sync::Arc;
use k256::sha2::{Sha256, Digest};

#[derive(CandidType, Deserialize, Debug)]
struct PublicKeyArgument {
}

#[derive(CandidType, Deserialize, Debug)]
struct PublicKeyReply {
    pub public_key: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug)]
struct SignatureReply {
    pub signature: Vec<u8>,
}


pub struct CanisterIdentity {
    pub canister: Principal,
    pub identity: Arc<dyn Identity>,
    pub fetch_root_key: bool,
    pub handle: Handle,
}

impl CanisterIdentity {
    pub fn new(canister: Principal, identity: Arc<dyn Identity>, fetch_root_key: bool, handle: Handle) -> Self {
        Self { canister, identity, fetch_root_key, handle }
    }

    pub fn canister_update<A, R>(&self, method_name: &str, arg: &A) -> Result<R, String>
        where
            A: CandidType,
            R: CandidType + DeserializeOwned
    {
        let (tx, rx) = channel::bounded(1);
        let identity = self.identity.clone();
        let canister = self.canister.clone();
        let fetch_root_key = self.fetch_root_key.clone();
        let arg_bytes = Encode!(&arg).map_err(|e| format!("{e}"))?;
        let method = method_name.to_string();
        self.handle.spawn(async move {
            let agent = get_agent_async(identity, fetch_root_key).await;
            let _ = tx.send(match agent {
                Err(e) => Err(e),
                Ok(agent) => {
                    agent.update(&canister, method)
                        .with_arg(&arg_bytes)
                        .call_and_wait(TimeoutWaiter::new(std::time::Duration::from_secs(60 * 5)))
                        .await
                        .map_err(|err| anyhow!(err))
                }
            });
        });
        let r = rx.recv();
        let bytes = r.map_err(|e| format!("{e}"))?.map_err(|e| format!("{e}"))?;
        let result = Decode!(&bytes, Result<R, String>).map_err(|e| format!("{e}"))?;
        return Ok(result?);
    }

    fn public_key(&self) -> Result<Vec<u8>, String> {
        let result: PublicKeyReply = self.canister_update("public_key", &PublicKeyArgument { })?;
        assert!(result.public_key.len() == 33, "malformed public_key, len: {}, expected 33", result.public_key.len());
        Ok(result.public_key)
    }
}

impl Identity for CanisterIdentity {
    fn sender(&self) -> Result<Principal, String> {
        let public_key = self.public_key()?;
        eprintln!("public key: {}", hex::encode(&public_key));
        Ok(Principal::self_authenticating(&public_key))
    }

    fn sign(&self, blob: &[u8]) -> Result<Signature, String> {
        let mut hasher = Sha256::new();
        hasher.update(blob);
        let message: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();
        let result: SignatureReply = self.canister_update("sign", &message)?;
        // TODO: We need a public key here not a principal
        let public_key = self.public_key()?;
        eprintln!("signature public key: {}", hex::encode(&public_key));
        Ok(Signature {
            public_key: Some(public_key),
            signature: Some(result.signature),
        })
    }
}

fn get_agent(identity: Arc<dyn Identity>) -> anyhow::Result<Agent> {
    let timeout = std::time::Duration::from_secs(60 * 5);
    Agent::builder()
        .with_transport(
            ic_agent::agent::http_transport::ReqwestHttpReplicaV2Transport::create({
                get_ic_url()
            })?,
        )
        .with_ingress_expiry(Some(timeout))
        .with_arc_identity(identity)
        .build()
        .map_err(|err| anyhow!(err))
}

const IC_URL: &str = "https://ic0.app";

fn get_ic_url() -> String {
    std::env::var("IC_URL").unwrap_or_else(|_| IC_URL.to_string())
}

async fn get_agent_async(identity: Arc<dyn Identity>, fetch_root_key: bool) -> anyhow::Result<Agent> {
    let agent = get_agent(identity)?;
    if fetch_root_key {
        agent.fetch_root_key().await?;
    }
    Ok(agent)
}

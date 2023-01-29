use anyhow::anyhow;
use ic_agent::{
    export::Principal,
    Agent, Identity, Signature,
};
use candid::{Encode, Decode, CandidType};
use serde::{Deserialize, Serialize};
use garcon::TimeoutWaiter;
use tokio::runtime::Handle;
use crossbeam::channel;
use std::sync::Arc;

#[derive(CandidType, Deserialize, Debug)]
struct PublicKeyArgument {
}

#[derive(CandidType, Deserialize, Debug)]
struct PublicKeyReply {
    pub public_key: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug)]
struct SignArgument {
  message: Option<Vec<u8>>,
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
}

impl Identity for CanisterIdentity {
    fn sender(&self) -> Result<Principal, String> {
        let (tx, rx) = channel::bounded(1);
        let identity = self.identity.clone();
        let canister = self.canister.clone();
        let fetch_root_key = self.fetch_root_key.clone();
        let arg = Encode!(&PublicKeyArgument { }).map_err(|e| format!("{e}"))?;
        self.handle.spawn(async move {
            let agent = get_agent_async(identity, fetch_root_key).await;
            let _ = tx.send(match agent {
                Err(e) => Err(e),
                Ok(agent) => {
                    agent.update(&canister, "public_key")
                        .with_arg(&arg)
                        .call_and_wait(TimeoutWaiter::new(std::time::Duration::from_secs(60 * 5)))
                        .await
                        .map_err(|err| anyhow!(err))
                }
            });
        });
        let r = rx.recv();
        let response = r.map_err(|e| format!("{e}"))?.map_err(|e| format!("{e}"))?;
        let result = Decode!(response.as_slice(), Result<PublicKeyReply, String>).map_err(|e| format!("{e}"))?;
        Ok(Principal::self_authenticating(&result?.public_key))
    }

    fn sign(&self, blob: &[u8]) -> Result<Signature, String> {
        eprintln!("canister_identity.sign({})", hex::encode(&blob));
        let (tx, rx) = channel::bounded(1);
        let identity = self.identity.clone();
        let canister = self.canister.clone();
        let fetch_root_key = self.fetch_root_key.clone();
        let message = Some(blob.to_vec());
        let arg = Encode!(&SignArgument { message }).map_err(|e| format!("{e}"))?;
        self.handle.spawn(async move {
            eprintln!("getting agent");
            let agent = get_agent_async(identity, fetch_root_key).await;
            eprintln!("got agent");
            let _ = tx.send(match agent {
                Err(e) => Err(e),
                Ok(agent) => {
                    eprintln!("getting signature");
                    agent.update(&canister, "sign")
                        .with_arg(&arg)
                        .call_and_wait(TimeoutWaiter::new(std::time::Duration::from_secs(60 * 5)))
                        .await
                        .map_err(|err| anyhow!(err))
                }
            });
        });
        let r = rx.recv();
        eprintln!("sign response: {r:?}");
        let response = r.map_err(|e| format!("{e}"))?.map_err(|e| format!("{e}"))?;
        let result = Decode!(response.as_slice(), Result<SignatureReply, String>).map_err(|e| format!("{e}"))?;
        Ok(Signature {
            public_key: Some(self.sender()?.as_slice().to_vec()),
            signature: Some(result?.signature),
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

//! keycraft: the identities of a person on this node, over the keys
//! delegate. The one place keys are created, imported, exported, renamed and
//! removed; every other craftworks app only picks one.
use std::rc::Rc;
use std::sync::Arc;

use craftworks_page::accounts::Accounts;
use craftworks_page::home::Homes;
use craftworks_page::keys::Keys;
use craftworks_page::{hex, parse32, BrowserClient, Events};
use datacraft_keys_proto::{Reply, Request};
use serde_json::json;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Wallet {
    client: Arc<BrowserClient>,
    keys: Rc<Keys>,
    homes: Homes,
}

#[wasm_bindgen]
impl Wallet {
    pub async fn connect(ws_url: String, on_event: js_sys::Function) -> Result<Wallet, JsValue> {
        console_error_panic_hook::set_once();
        let events = Events::new(on_event);
        let client = Arc::new(
            BrowserClient::connect(&ws_url)
                .await
                .map_err(|e| e.to_string())?,
        );
        let keys = Rc::new(Keys::install(client.clone()).await?);
        Ok(Wallet {
            client,
            keys,
            homes: Homes::new(events),
        })
    }

    pub fn delegate_key(&self) -> String {
        self.keys.delegate_key()
    }

    /// JSON {people: [identity…], communities: [identity…]} where an identity
    /// is {name, owner, can_sign, kind, home: seq|null, dbs: [{name, address}], error?}.
    pub async fn identities(&self) -> Result<String, JsValue> {
        let (mut people, mut communities) =
            Accounts::list(self.client.clone(), &self.keys, &self.homes).await?;
        for item in people.iter_mut().chain(communities.iter_mut()) {
            let name = item["name"].as_str().unwrap_or_default().to_string();
            item["home"] = json!(self.homes.seq(&name));
            item["dbs"] = match self.homes.databases(&name).await {
                Ok(dbs) => json!(dbs),
                Err(e) => {
                    item["error"] = json!(e);
                    json!([])
                }
            };
        }
        Ok(json!({"people": people, "communities": communities}).to_string())
    }

    /// A new identity: key set, home drive, kind mark. Returns the owner key (hex).
    pub async fn create(&self, name: String) -> Result<String, JsValue> {
        let owner = Accounts::create_person(self.client.clone(), &self.keys, &self.homes, &name).await?;
        Ok(hex(&owner))
    }

    /// A key set from another device or a backup; a store key alone makes a
    /// read-only entry. Returns the owner key (hex), empty for read-only.
    pub async fn import(
        &self,
        name: String,
        signing_key_hex: String,
        store_key_hex: String,
    ) -> Result<String, JsValue> {
        let name = name.trim().to_string();
        if name.is_empty() || name.len() > 64 {
            return Err("a name is 1 to 64 characters".into());
        }
        let signing_key = if signing_key_hex.trim().is_empty() {
            None
        } else {
            Some(parse32(&signing_key_hex)?)
        };
        let store_key = parse32(&store_key_hex)?;
        match self
            .keys
            .call(Request::Import {
                name: name.clone(),
                signing_key,
                store_key,
            })
            .await?
        {
            Reply::Imported { owner } => {
                // its home drive is already on the network when the set came from another device
                let _ = self
                    .homes
                    .ensure(self.client.clone(), &self.keys, &name)
                    .await;
                Ok(owner.map(|o| hex(&o)).unwrap_or_default())
            }
            other => Err(format!("unexpected: {other:?}").into()),
        }
    }

    /// JSON {signing_key, store_key, owner}; signing_key empty for a read-only set.
    pub async fn export(&self, name: String) -> Result<String, JsValue> {
        match self.keys.call(Request::Export { name }).await? {
            Reply::Exported {
                signing_key,
                store_key,
                owner,
            } => Ok(json!({
                "signing_key": signing_key.map(|k| hex(&k)).unwrap_or_default(),
                "store_key": hex(&store_key),
                "owner": owner.map(|o| hex(&o)).unwrap_or_default(),
            })
            .to_string()),
            other => Err(format!("unexpected: {other:?}").into()),
        }
    }

    pub async fn remove(&self, name: String) -> Result<(), JsValue> {
        self.keys.call(Request::Remove { name }).await?;
        Ok(())
    }

    /// A new label for a key set: the delegate has no rename, so this is
    /// export, import under the new name, remove the old. The keys, the
    /// owner and everything on the network are unchanged.
    pub async fn rename(&self, old: String, new: String) -> Result<(), JsValue> {
        let new = new.trim().to_string();
        if new.is_empty() || new.len() > 64 {
            return Err("a name is 1 to 64 characters".into());
        }
        if new == old {
            return Ok(());
        }
        let (signing_key, store_key) = match self.keys.call(Request::Export { name: old.clone() }).await? {
            Reply::Exported {
                signing_key,
                store_key,
                ..
            } => (signing_key, store_key),
            other => return Err(format!("unexpected: {other:?}").into()),
        };
        match self
            .keys
            .call(Request::Import {
                name: new,
                signing_key,
                store_key,
            })
            .await?
        {
            Reply::Imported { .. } => {}
            other => return Err(format!("unexpected: {other:?}").into()),
        }
        self.keys.call(Request::Remove { name: old }).await?;
        Ok(())
    }
}

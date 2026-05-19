use std::{collections::HashMap, sync::Arc, time::Duration};

use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};
use tokio::{net::UdpSocket, sync::RwLock};
use uuid::Uuid;

use crate::{db::now, state::DiscoveredPeer};

#[derive(Serialize, Deserialize, Debug)]
pub struct BeaconPacket {
    pub user_hash: String,
    pub pubkey_fingerprint: String,
    pub replication_port: u16,
    pub nonce: String,
    pub nonce_sig: String,
}

pub async fn run_udp_beacon_broadcaster(signing_key: Arc<SigningKey>, node_id: String) {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ UDP broadcaster bind failed: {e}");
            return;
        }
    };
    sock.set_broadcast(true).ok();

    loop {
        let nonce = Uuid::new_v4().to_string();
        let sig: Signature = signing_key.sign(nonce.as_bytes());
        let packet = BeaconPacket {
            user_hash: "anonymous".to_string(),
            pubkey_fingerprint: node_id.clone(),
            replication_port: 11204,
            nonce: nonce.clone(),
            nonce_sig: hex::encode(sig.to_bytes()),
        };
        if let Ok(json) = serde_json::to_vec(&packet) {
            let _ = sock.send_to(&json, "255.255.255.255:8765").await;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

pub async fn run_udp_beacon_listener(peers: Arc<RwLock<HashMap<String, DiscoveredPeer>>>) {
    let sock = match UdpSocket::bind("0.0.0.0:8765").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ UDP listener bind failed (port 8765): {e}");
            return;
        }
    };
    let mut buf = [0u8; 4096];
    println!("📡 UDP beacon listener on port 8765");

    loop {
        let (len, src) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let Ok(packet) = serde_json::from_slice::<BeaconPacket>(&buf[..len]) else {
            continue;
        };

        let peer = DiscoveredPeer {
            addr: src.ip().to_string(),
            user_hash: packet.user_hash.clone(),
            pubkey_fingerprint: packet.pubkey_fingerprint.clone(),
            replication_port: packet.replication_port,
            last_seen: now(),
        };
        peers.write().await.insert(packet.pubkey_fingerprint, peer);
    }
}

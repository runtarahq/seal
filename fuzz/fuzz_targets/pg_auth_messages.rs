//! Whatever a Postgres server sends during a login, seal never panics, and never sends
//! the password itself unless the rule allows a cleartext password.
//!
//! The first byte sets the rule's flags; the rest is what the server sends.

#![no_main]

use libfuzzer_sys::fuzz_target;
use seal_broker::pg::login::{Credentials, login};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PASSWORD: &[u8] = b"SEALCANARY-password";

fuzz_target!(|data: &[u8]| {
    let Some((&flags, server_bytes)) = data.split_first() else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let (mut from_client, mut to_client) = tokio::io::split(server);
        to_client.write_all(server_bytes).await.expect("it fits");
        to_client.shutdown().await.expect("shut down");
        drop(to_client);
        let allow_cleartext = flags & 2 != 0;
        let credentials = Credentials {
            user: "app_user",
            password: Some(PASSWORD),
            allow_md5: flags & 1 != 0,
            allow_cleartext,
            require_channel_binding: flags & 16 != 0,
            client_cert: flags & 4 != 0,
            end_point: (flags & 8 != 0).then(|| vec![7; 32]),
        };
        let _ = login(&mut client, &credentials).await;
        drop(client);
        let mut sent = Vec::new();
        let _ = from_client.read_to_end(&mut sent).await;
        if !allow_cleartext {
            assert!(
                !sent.windows(PASSWORD.len()).any(|window| window == PASSWORD),
                "the password was sent in the clear"
            );
        }
    });
});

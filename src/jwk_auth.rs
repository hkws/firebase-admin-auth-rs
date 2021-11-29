use crate::jwk::{fetch_keys, JwkKeys};
use crate::verifier::{Claims, JwkVerifier};
use jsonwebtoken::TokenData;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use log::{info};
use tokio::time::sleep;
use tokio::task::JoinHandle;

// type Delay = Duration;
// type Cancel = Box<dyn Fn() -> () + Send>;
// type CleanupFn = Box<dyn Fn() -> () + Send>;

// verifierはメインスレッドで参照、key更新用のスレッドで更新されるため、
// スレッド間でメモリを共有できるよう実装する必要がある
// そこで、Mutexを利用する。Mutexには以下の制約があることにより、複数スレッドで同じデータを共有できる。
// 1. Mutexにあるデータを利用するためには、事前にlockの獲得を試みる。他者がlockを獲得していたらunlockされるまで待つ。
// 2. データを使い終わったらunlockする
// ※ rustにおいて、1については明示的に実装に書く必要があるが、2はdrop時に自動的にunlockされるので気にしなくて良い = unlock忘れが起きない
// ただし、単に `verifier: Mutex<JwkVerifier>`　としてもコンパイルが通らない。
// なぜならkey更新用スレッドにverifierがmoveされてしまうため、メインスレッドでverifierを参照できなくなるためである。
// 要するに、a. 一つの値（verifier）が複数の所有権を持てる, b. 一度に可変参照を取得できるのは1スレッドのみ
// という２つの条件を同時に満たさなければならない
// bはMutexの導入で解ける。そしてaは参照カウント(Rc)を使って解ける。Rc型の値はcloneすることで同じメモリを指す複数の所有権を生成できるのだ。
// ただし、Rcはスレッド間でデータを共有するには安全でない（スレッドセーフでない。替わりにパフォーマンスが良い）ため、Arcを使う。
//   Send: Sendを実装した型は所有権をスレッド間で転送できる。Rc<T>はこれを満たさない。
//   Sync: 複数のスレッドからの参照を許可する。Rc<T>はこれを満たさない。
// #[derive(Clone)]
pub struct JwkAuth {
    verifier: Arc<Mutex<JwkVerifier>>,
    task_handler: Arc<Mutex<Box<JoinHandle<()>>>>
}

impl Drop for JwkAuth {
    fn drop(&mut self) {
        let handler = self.task_handler.lock().unwrap();
        handler.abort();
    }
}

impl JwkAuth {
    pub async fn new() -> JwkAuth {
        let jwk_key_result = fetch_keys().await;
        let jwk_keys: JwkKeys = match jwk_key_result {
            Ok(keys) => keys,
            Err(_) => {
                panic!("Unable to fetch jwk keys! Cannot verify user tokens!")
            }
        };
        let verifier = Arc::new(Mutex::new(JwkVerifier::new(jwk_keys.keys)));
        let mut instance = JwkAuth {
            verifier: verifier,
            task_handler: Arc::new(Mutex::new(Box::new(tokio::spawn(async {}))))
        };
        instance.start_periodic_key_update();
        instance
    }
    pub fn verify(&self, token: &String) -> Option<TokenData<Claims>> {
        let verifier = self.verifier.lock().unwrap();
        verifier.verify(token)
    }
    fn start_periodic_key_update(&mut self) {
        let verifier_ref = Arc::clone(&self.verifier);
        let task = tokio::spawn(async move {
            loop {
                let delay = match fetch_keys().await {
                    Ok(jwk_keys) => {
                        {
                            let mut verifier = verifier_ref.lock().unwrap();
                            verifier.set_keys(jwk_keys.keys);
                        }
                        info!("Updated JWK Keys. Next refresh will be in {:?}", jwk_keys.validity);
                        jwk_keys.validity
                    },
                    Err(_) => Duration::from_secs(60)
                };
                sleep(delay).await;
            }
        });
        let mut handler = self.task_handler.lock().unwrap();
        *handler = Box::new(task);
    }
}

// // mpsc: multiple producer. single consumer
// // 複数の送信側txと値を消費する一つの受信側rxを持てる。よってtxはcloneできる。
// // 何かしらチャンネルを通じてrecvされるまで、delay秒毎に公開鍵の更新を続ける
// let (shutdown_tx, shutdown_rx) = mpsc::channel();
// thread::spawn(move || async {
//     loop {
//         let delay = job().await;
//         thread::sleep(delay);
//         if let Ok(_) | Err(TryRecvError::Disconnected) = shutdown_rx.try_recv() {
//             break;
//         }
//     }
// });
// // periodicな公開鍵更新を、txからメッセージを送ることで停止する
// // ここでBoxされた停止用関数は、JwkAuthのcleanupとして保持され、
// // JwkAuthのdrop時（すなわちmain終了時）に実行される。
// Box::new(move || {
//     info!("Stopping...");
//     let _ = shutdown_tx.send("send");
// })

// use crate::auth::jwk::{fetch_keys, JwkKeys};
// use crate::auth::verifier::{Claims, JwkVerifier};
// use jsonwebtoken::TokenData;
// use std::sync::{Arc, Mutex};
// use std::time::Duration;
// use actix::prelude::*;

// type Delay = Duration;

// // verifierはメインスレッドで参照、key更新用のスレッドで更新されるため、
// // スレッド間でメモリを共有できるよう実装する必要がある
// // そこで、Mutexを利用する。Mutexには以下の制約があることにより、複数スレッドで同じデータを共有できる。
// // 1. Mutexにあるデータを利用するためには、事前にlockの獲得を試みる。他者がlockを獲得していたらunlockされるまで待つ。
// // 2. データを使い終わったらunlockする
// // ※ rustにおいて、1については明示的に実装に書く必要があるが、2はdrop時に自動的にunlockされるので気にしなくて良い = unlock忘れが起きない
// // ただし、単に `verifier: Mutex<JwkVerifier>`　としてもコンパイルが通らない。
// // なぜならkey更新用スレッドにverifierがmoveされてしまうため、メインスレッドでverifierを参照できなくなるためである。
// // 要するに、a. 一つの値（verifier）が複数の所有権を持てる, b. 一度に可変参照を取得できるのは1スレッドのみ
// // という２つの条件を同時に満たさなければならない
// // bはMutexの導入で解ける。そしてaは参照カウント(Rc)を使って解ける。Rc型の値はcloneすることで同じメモリを指す複数の所有権を生成できるのだ。
// // ただし、Rcはスレッド間でデータを共有するには安全でない（スレッドセーフでない。替わりにパフォーマンスが良い）ため、Arcを使う。
// //   Send: Sendを実装した型は所有権をスレッド間で転送できる。Rc<T>はこれを満たさない。
// //   Sync: 複数のスレッドからの参照を許可する。Rc<T>はこれを満たさない。
// pub struct JwkAuth {
//     verifier: Arc<Mutex<JwkVerifier>>,
//     handler: Option<SpawnHandle>
// }

// impl Actor for JwkAuth {
//     type Context = Context<Self>;
//     fn started(&mut self, ctx: &mut Context<Self>) {
//         println!("JwkAuth is started");
//         self.handler = Some(
//             ctx.run_later(Duration::from_secs(1), move |this: &mut Self, ctx| {
//                 this.schedule_refresh(ctx)
//             })
//         );
//     }
//     fn stopped(&mut self, ctx: &mut Context<Self>) {
//         if let Some(handler) = self.handler {
//             ctx.cancel_future(handler);
//             println!("JwkAuth is finished");
//         }
//     }
// }

// impl JwkAuth {
//     pub fn new(ctx: &mut Context<Self>) -> JwkAuth {
//         let jwk_key_result = fetch_keys();
//         let jwk_keys: JwkKeys = match jwk_key_result {
//             Ok(keys) => keys,
//             Err(_) => {
//                 panic!("Unable to fetch jwk keys! Cannot verify user tokens!")
//             }
//         };
//         let verifier = Arc::new(Mutex::new(JwkVerifier::new(jwk_keys.keys)));
//         let auth = JwkAuth {
//             verifier: verifier,
//             handler: None
//         };
//         auth.started(ctx);
//         auth
//     }
//     pub fn verify(&self, token: &String) -> Option<TokenData<Claims>> {
//         let verifier = self.verifier.lock().unwrap();
//         verifier.verify(token)
//     }
//     pub fn schedule_refresh(&mut self, ctx: &mut Context<Self>) {
//         let verifier_ref = Arc::clone(&self.verifier);
//         let delay = match fetch_keys() {
//             Ok(jwk_keys) => {
//                 let mut verifier = verifier_ref.lock().unwrap();
//                 verifier.set_keys(jwk_keys.keys);
//                 println!("Updated JWK Keys. Next refresh will be in {:?}", jwk_keys.validity);
//                 jwk_keys.validity
//             },
//             Err(_) => Duration::from_secs(10)
//         };
//         self.handler = Some(
//             ctx.run_later(delay, move |this: &mut Self, ctx| {
//                 this.schedule_refresh(ctx)
//             })
//         );
//     }
// }

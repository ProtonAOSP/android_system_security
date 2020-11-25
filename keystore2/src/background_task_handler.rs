// Copyright 2020, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module implements the handling of background tasks such as obtaining timestamp tokens from
//! the timestamp service (or TEE KeyMint in legacy devices), via a separate thread.

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, IKeyMintDevice::IKeyMintDevice,
    SecurityLevel::SecurityLevel, VerificationToken::VerificationToken,
};
use android_system_keystore2::aidl::android::system::keystore2::OperationChallenge::OperationChallenge;
use anyhow::Result;
use log::error;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Mutex;
use std::thread::{spawn, JoinHandle};
/// This is the struct encapsulating the thread which handles background tasks such as
/// obtaining verification tokens.
pub struct BackgroundTaskHandler {
    task_handler: Mutex<Option<JoinHandle<()>>>,
}
/// This enum defines the two variants of a message that can be passed down to the
/// BackgroundTaskHandler via the channel.
pub enum Message {
    ///This variant represents a message sent down the channel when requesting a timestamp token.
    Inputs((HardwareAuthToken, OperationChallenge, Sender<(HardwareAuthToken, VerificationToken)>)),
    ///This variant represents a message sent down the channel when signalling the thread to stop.
    Shutdown,
}

impl BackgroundTaskHandler {
    /// Initialize the BackgroundTaskHandler with the task_handler field set to None.
    /// The thread is not started during initialization, as it needs the receiver end of a channel
    /// to function.
    pub fn new() -> Self {
        BackgroundTaskHandler { task_handler: Mutex::new(None) }
    }

    /// Start the background task handler (bth) by passing in the receiver end of a channel, through
    /// which the enforcement module can send messages to the bth thread.
    pub fn start_bth(&self, receiver: Receiver<Message>) -> Result<()> {
        let task_handler = Self::start_thread(receiver)?;
        // it is ok to unwrap here because there is no way that this lock can get poisoned.
        let mut thread_guard = self.task_handler.lock().unwrap();
        *thread_guard = Some(task_handler);
        Ok(())
    }

    fn start_thread(receiver: Receiver<Message>) -> Result<JoinHandle<()>> {
        // TODO: initialize timestamp service/keymint instances.
        // First lookup timestamp token service, if this is not a legacy device.
        // Otherwise, lookup keymaster 4.1 or 4.0 (previous ones are not relevant, because strongbox
        // was introduced with keymaster 4.0).
        // If either a timestamp service or a keymint instance is expected to be found and neither
        // is found, an error is returned.
        // If neither is expected to be found, make timestamp_service field None, and in the thread,
        // send a default verification token down the channel to the operation.
        // Until timestamp service is available and proper probing of legacy keymaster devices are
        // done, the keymint service is initialized here as it is done in security_level module.
        Ok(spawn(move || {
            while let Message::Inputs((auth_token, op_challenge, op_sender)) = receiver
                .recv()
                .expect(
                "In background task handler thread. Failed to receive message over the channel.",
            ) {
                // TODO: call the timestamp service/old TEE keymaster to get
                // timestamp/verification tokens and pass it down the sender that is
                // coupled with a particular operation's receiver.
                // If none of the services are available, pass the authtoken and a default
                // verification token down the channel.
                let km_dev: Box<dyn IKeyMintDevice> =
                    crate::globals::get_keymint_device(SecurityLevel::TRUSTED_ENVIRONMENT)
                        .expect("A TEE Keymint must be present.")
                        .get_interface()
                        .expect("Fatal: The keymint device does not implement IKeyMintDevice.");
                let result = km_dev.verifyAuthorization(op_challenge.challenge, &auth_token);
                match result {
                    Ok(verification_token) => {
                        // this can fail if the operation is dropped and hence the channel
                        // is hung up.
                        op_sender.send((auth_token, verification_token)).unwrap_or_else(|e| {
                            error!(
                                "In background task handler thread. Failed to send
                                         verification token to operation {} due to error {:?}.",
                                op_challenge.challenge, e
                            )
                        });
                    }
                    Err(e) => {
                        // log error
                        error!(
                            "In background task handler thread. Failed to receive
                                     verification token for operation {} due to error {:?}.",
                            op_challenge.challenge, e
                        );
                        // send default verification token
                        // this can fail if the operation is dropped and the channel is
                        // hung up.
                        op_sender.send((auth_token, VerificationToken::default())).unwrap_or_else(
                            |e| {
                                error!(
                                    "In background task handler thread. Failed to send default
                                         verification token to operation {} due to error {:?}.",
                                    op_challenge.challenge, e
                                )
                            },
                        );
                    }
                }
            }
        }))
    }
}

impl Default for BackgroundTaskHandler {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: Verify if we want the thread to finish the requests they are working on, during drop.
impl Drop for BackgroundTaskHandler {
    fn drop(&mut self) {
        // it is ok to unwrap here as there is no way this lock can get poisoned.
        let mut thread_guard = self.task_handler.lock().unwrap();
        if let Some(thread) = (*thread_guard).take() {
            // TODO: Verify how best to handle the error in this case.
            thread.join().unwrap_or_else(|e| {
                panic!("Failed to join the background task handling thread because of {:?}.", e);
            });
        }
    }
}

// Copyright 2021, The Android Open Source Project
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

//! This module implements the shared secret negotiation.

use crate::error::{map_binder_status, map_binder_status_code, Error};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use android_hardware_security_keymint::binder::Strong;
use android_hardware_security_sharedsecret::aidl::android::hardware::security::sharedsecret::{
    ISharedSecret::ISharedSecret, SharedSecretParameters::SharedSecretParameters,
};
use android_security_compat::aidl::android::security::compat::IKeystoreCompatService::IKeystoreCompatService;
use anyhow::{Context, Result};
use keystore2_vintf::{get_aidl_instances, get_hidl_instances};
use std::fmt::{self, Display, Formatter};

/// This function initiates the shared secret negotiation. It starts a thread and then returns
/// immediately. The thread consults the vintf manifest to enumerate expected negotiation
/// participants. It then attempts to connect to all of these participants. If any connection
/// fails the thread will retry once per second to connect to the failed instance(s) until all of
/// the instances are connected. It then performs the negotiation.
///
/// During the first phase of the negotiation it will again try every second until
/// all instances have responded successfully to account for instances that register early but
/// are not fully functioning at this time due to hardware delays or boot order dependency issues.
/// An error during the second phase or a checksum mismatch leads to a panic.
pub fn perform_shared_secret_negotiation() {
    std::thread::spawn(|| {
        let participants = list_participants()
            .expect("In perform_shared_secret_negotiation: Trying to list participants.");
        let connected = connect_participants(participants);
        negotiate_shared_secret(connected);
        log::info!("Shared secret negotiation concluded successfully.");
    });
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SharedSecretParticipant {
    /// Represents an instance of android.hardware.security.sharedsecret.ISharedSecret.
    Aidl(String),
    /// In the legacy case there can be at most one TEE and one Strongbox hal.
    Hidl { is_strongbox: bool, version: (usize, usize) },
}

impl Display for SharedSecretParticipant {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Aidl(instance) => write!(
                f,
                "{}.{}/{}",
                SHARED_SECRET_PACKAGE_NAME, SHARED_SECRET_INTERFACE_NAME, instance
            ),
            Self::Hidl { is_strongbox, version: (ma, mi) } => write!(
                f,
                "{}@V{}.{}::{}/{}",
                KEYMASTER_PACKAGE_NAME,
                ma,
                mi,
                KEYMASTER_INTERFACE_NAME,
                if *is_strongbox { "strongbox" } else { "default" }
            ),
        }
    }
}

#[derive(thiserror::Error, Debug)]
enum SharedSecretError {
    #[error("Shared parameter retrieval failed on instance {p} with error {e:?}.")]
    ParameterRetrieval { e: Error, p: SharedSecretParticipant },
    #[error("Shared secret computation failed on instance {p} with error {e:?}.")]
    Computation { e: Error, p: SharedSecretParticipant },
    #[error("Checksum comparison failed on instance {0}.")]
    Checksum(SharedSecretParticipant),
}

fn filter_map_legacy_km_instances(
    name: String,
    version: (usize, usize),
) -> Option<SharedSecretParticipant> {
    match name.as_str() {
        "default" => Some(SharedSecretParticipant::Hidl { is_strongbox: false, version }),
        "strongbox" => Some(SharedSecretParticipant::Hidl { is_strongbox: true, version }),
        _ => {
            log::warn!("Found unexpected keymaster instance: \"{}\"", name);
            log::warn!("Device is misconfigured. Allowed instances are:");
            log::warn!("   * default");
            log::warn!("   * strongbox");
            None
        }
    }
}

static KEYMASTER_PACKAGE_NAME: &str = "android.hardware.keymaster";
static KEYMASTER_INTERFACE_NAME: &str = "IKeymasterDevice";
static SHARED_SECRET_PACKAGE_NAME: &str = "android.hardware.security.sharedsecret";
static SHARED_SECRET_INTERFACE_NAME: &str = "ISharedSecret";
static COMPAT_PACKAGE_NAME: &str = "android.security.compat";

/// Lists participants.
fn list_participants() -> Result<Vec<SharedSecretParticipant>> {
    Ok([(4, 0), (4, 1)]
        .iter()
        .map(|(ma, mi)| {
            get_hidl_instances(KEYMASTER_PACKAGE_NAME, *ma, *mi, KEYMASTER_INTERFACE_NAME)
                .as_vec()
                .with_context(|| format!("Trying to convert KM{}.{} names to vector.", *ma, *mi))
                .map(|instances| {
                    instances
                        .into_iter()
                        .filter_map(|name| {
                            filter_map_legacy_km_instances(name.to_string(), (*ma, *mi))
                        })
                        .collect::<Vec<SharedSecretParticipant>>()
                })
        })
        .collect::<Result<Vec<_>>>()
        .map(|v| v.into_iter().flatten())
        .and_then(|i| {
            let participants_aidl: Vec<SharedSecretParticipant> =
                get_aidl_instances(SHARED_SECRET_PACKAGE_NAME, 1, SHARED_SECRET_INTERFACE_NAME)
                    .as_vec()
                    .context("In list_participants: Trying to convert KM1.0 names to vector.")?
                    .into_iter()
                    .map(|name| SharedSecretParticipant::Aidl(name.to_string()))
                    .collect();
            Ok(i.chain(participants_aidl.into_iter()))
        })
        .context("In list_participants.")?
        .collect())
}

fn connect_participants(
    mut participants: Vec<SharedSecretParticipant>,
) -> Vec<(Strong<dyn ISharedSecret>, SharedSecretParticipant)> {
    let mut connected_participants: Vec<(Strong<dyn ISharedSecret>, SharedSecretParticipant)> =
        vec![];
    loop {
        let (connected, not_connected) = participants.into_iter().fold(
            (connected_participants, vec![]),
            |(mut connected, mut failed), e| {
                match e {
                    SharedSecretParticipant::Aidl(instance_name) => {
                        let service_name = format!(
                            "{}.{}/{}",
                            SHARED_SECRET_PACKAGE_NAME, SHARED_SECRET_INTERFACE_NAME, instance_name
                        );
                        match map_binder_status_code(binder::get_interface(&service_name)) {
                            Err(e) => {
                                log::warn!(
                                    "Unable to connect \"{}\" with error:\n{:?}\nRetrying later.",
                                    service_name,
                                    e
                                );
                                failed.push(SharedSecretParticipant::Aidl(instance_name));
                            }
                            Ok(service) => connected
                                .push((service, SharedSecretParticipant::Aidl(instance_name))),
                        }
                    }
                    SharedSecretParticipant::Hidl { is_strongbox, version } => {
                        // This is a no-op if it was called before.
                        keystore2_km_compat::add_keymint_device_service();

                        // If we cannot connect to the compatibility service there is no way to
                        // recover.
                        // PANIC! - Unless you brought your towel.
                        let keystore_compat_service: Strong<dyn IKeystoreCompatService> =
                            map_binder_status_code(binder::get_interface(COMPAT_PACKAGE_NAME))
                                .expect(
                                    "In connect_participants: Trying to connect to compat service.",
                                );

                        match map_binder_status(keystore_compat_service.getSharedSecret(
                            if is_strongbox {
                                SecurityLevel::STRONGBOX
                            } else {
                                SecurityLevel::TRUSTED_ENVIRONMENT
                            },
                        )) {
                            Err(e) => {
                                log::warn!(
                                    concat!(
                                        "Unable to connect keymaster device \"{}\" ",
                                        "with error:\n{:?}\nRetrying later."
                                    ),
                                    if is_strongbox { "strongbox" } else { "TEE" },
                                    e
                                );
                                failed
                                    .push(SharedSecretParticipant::Hidl { is_strongbox, version });
                            }
                            Ok(service) => connected.push((
                                service,
                                SharedSecretParticipant::Hidl { is_strongbox, version },
                            )),
                        }
                    }
                }
                (connected, failed)
            },
        );
        participants = not_connected;
        connected_participants = connected;
        if participants.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
    connected_participants
}

fn negotiate_shared_secret(
    participants: Vec<(Strong<dyn ISharedSecret>, SharedSecretParticipant)>,
) {
    // Phase 1: Get the sharing parameters from all participants.
    let mut params = loop {
        let result: Result<Vec<SharedSecretParameters>, SharedSecretError> = participants
            .iter()
            .map(|(s, p)| {
                map_binder_status(s.getSharedSecretParameters())
                    .map_err(|e| SharedSecretError::ParameterRetrieval { e, p: (*p).clone() })
            })
            .collect();

        match result {
            Err(e) => {
                log::warn!("{:?}", e);
                log::warn!("Retrying in one second.");
                std::thread::sleep(std::time::Duration::from_millis(1000));
            }
            Ok(params) => break params,
        }
    };

    params.sort_unstable();

    // Phase 2: Send the sorted sharing parameters to all participants.
    participants
        .into_iter()
        .try_fold(None, |acc, (s, p)| {
            match (acc, map_binder_status(s.computeSharedSecret(&params))) {
                (None, Ok(new_sum)) => Ok(Some(new_sum)),
                (Some(old_sum), Ok(new_sum)) => {
                    if old_sum == new_sum {
                        Ok(Some(old_sum))
                    } else {
                        Err(SharedSecretError::Checksum(p))
                    }
                }
                (_, Err(e)) => Err(SharedSecretError::Computation { e, p }),
            }
        })
        .expect("Fatal: Shared secret computation failed.");
}

#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::identity_op)]
#![allow(clippy::excessive_precision)]
#![allow(clippy::too_many_arguments)]
pub use binder::public_api as binder;
pub mod aidl {
  pub mod android {
    pub mod hardware {
      pub mod keymint {
        pub mod Algorithm {
          #![allow(non_upper_case_globals)]
          pub type Algorithm = i32;
          pub const RSA: Algorithm = 1;
          pub const EC: Algorithm = 3;
          pub const AES: Algorithm = 32;
          pub const TRIPLE_DES: Algorithm = 33;
          pub const HMAC: Algorithm = 128;
          pub(crate) mod mangled { pub use super::Algorithm as _7_android_8_hardware_7_keymint_9_Algorithm; }
        }
        pub mod BeginResult {
          pub struct BeginResult {
            pub challenge: i64, 
            pub params: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter>, 
            pub operation: Option<Box<dyn crate::mangled::_7_android_8_hardware_7_keymint_17_IKeyMintOperation>>, 
          }
          pub(crate) mod mangled { pub use super::BeginResult as _7_android_8_hardware_7_keymint_11_BeginResult; }
          impl Default for BeginResult {
            fn default() -> Self {
              Self {
                challenge: 0,
                params: Default::default(),
                operation: Default::default(),
              }
            }
          }
          impl binder::parcel::Serialize for BeginResult {
            fn serialize(&self, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              <Self as binder::parcel::SerializeOption>::serialize_option(Some(self), parcel)
            }
          }
          impl binder::parcel::SerializeArray for BeginResult {}
          impl binder::parcel::SerializeOption for BeginResult {
            fn serialize_option(this: Option<&Self>, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              let this = if let Some(this) = this {
                parcel.write(&1i32)?;
                this
              } else {
                return parcel.write(&0i32);
              };
              let start_pos = parcel.get_data_position();
              parcel.write(&0i32)?;
              parcel.write(&this.challenge)?;
              parcel.write(&this.params)?;
              let __field_ref = this.operation.as_ref().ok_or(binder::StatusCode::UNEXPECTED_NULL)?;
              parcel.write(__field_ref)?;
              let end_pos = parcel.get_data_position();
              let parcelable_size = (end_pos - start_pos) as i32;
              unsafe { parcel.set_data_position(start_pos)?; }
              parcel.write(&parcelable_size)?;
              unsafe { parcel.set_data_position(end_pos)?; }
              Ok(())
            }
          }
          impl binder::parcel::Deserialize for BeginResult {
            fn deserialize(parcel: &binder::parcel::Parcel) -> binder::Result<Self> {
              <Self as binder::parcel::DeserializeOption>::deserialize_option(parcel)
                 .transpose()
                 .unwrap_or(Err(binder::StatusCode::UNEXPECTED_NULL))
            }
          }
          impl binder::parcel::DeserializeArray for BeginResult {}
          impl binder::parcel::DeserializeOption for BeginResult {
            fn deserialize_option(parcel: &binder::parcel::Parcel) -> binder::Result<Option<Self>> {
              let status: i32 = parcel.read()?;
              if status == 0 { return Ok(None); }
              let start_pos = parcel.get_data_position();
              let parcelable_size: i32 = parcel.read()?;
              if parcelable_size < 0 { return Err(binder::StatusCode::BAD_VALUE); }
              let mut result = Self::default();
              result.challenge = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.params = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.operation = Some(parcel.read()?);
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod BlockMode {
          #![allow(non_upper_case_globals)]
          pub type BlockMode = i32;
          pub const ECB: BlockMode = 1;
          pub const CBC: BlockMode = 2;
          pub const CTR: BlockMode = 3;
          pub const GCM: BlockMode = 32;
          pub(crate) mod mangled { pub use super::BlockMode as _7_android_8_hardware_7_keymint_9_BlockMode; }
        }
        pub mod Certificate {
          pub struct Certificate {
            pub encodedCertificate: Vec<u8>, 
          }
          pub(crate) mod mangled { pub use super::Certificate as _7_android_8_hardware_7_keymint_11_Certificate; }
          impl Default for Certificate {
            fn default() -> Self {
              Self {
                encodedCertificate: Default::default(),
              }
            }
          }
          impl binder::parcel::Serialize for Certificate {
            fn serialize(&self, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              <Self as binder::parcel::SerializeOption>::serialize_option(Some(self), parcel)
            }
          }
          impl binder::parcel::SerializeArray for Certificate {}
          impl binder::parcel::SerializeOption for Certificate {
            fn serialize_option(this: Option<&Self>, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              let this = if let Some(this) = this {
                parcel.write(&1i32)?;
                this
              } else {
                return parcel.write(&0i32);
              };
              let start_pos = parcel.get_data_position();
              parcel.write(&0i32)?;
              parcel.write(&this.encodedCertificate)?;
              let end_pos = parcel.get_data_position();
              let parcelable_size = (end_pos - start_pos) as i32;
              unsafe { parcel.set_data_position(start_pos)?; }
              parcel.write(&parcelable_size)?;
              unsafe { parcel.set_data_position(end_pos)?; }
              Ok(())
            }
          }
          impl binder::parcel::Deserialize for Certificate {
            fn deserialize(parcel: &binder::parcel::Parcel) -> binder::Result<Self> {
              <Self as binder::parcel::DeserializeOption>::deserialize_option(parcel)
                 .transpose()
                 .unwrap_or(Err(binder::StatusCode::UNEXPECTED_NULL))
            }
          }
          impl binder::parcel::DeserializeArray for Certificate {}
          impl binder::parcel::DeserializeOption for Certificate {
            fn deserialize_option(parcel: &binder::parcel::Parcel) -> binder::Result<Option<Self>> {
              let status: i32 = parcel.read()?;
              if status == 0 { return Ok(None); }
              let start_pos = parcel.get_data_position();
              let parcelable_size: i32 = parcel.read()?;
              if parcelable_size < 0 { return Err(binder::StatusCode::BAD_VALUE); }
              let mut result = Self::default();
              result.encodedCertificate = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod Constants {
          #![allow(non_upper_case_globals)]
          pub type Constants = i32;
          pub const AUTH_TOKEN_MAC_LENGTH: Constants = 32;
          pub(crate) mod mangled { pub use super::Constants as _7_android_8_hardware_7_keymint_9_Constants; }
        }
        pub mod Digest {
          #![allow(non_upper_case_globals)]
          pub type Digest = i32;
          pub const NONE: Digest = 0;
          pub const MD5: Digest = 1;
          pub const SHA1: Digest = 2;
          pub const SHA_2_224: Digest = 3;
          pub const SHA_2_256: Digest = 4;
          pub const SHA_2_384: Digest = 5;
          pub const SHA_2_512: Digest = 6;
          pub(crate) mod mangled { pub use super::Digest as _7_android_8_hardware_7_keymint_6_Digest; }
        }
        pub mod EcCurve {
          #![allow(non_upper_case_globals)]
          pub type EcCurve = i32;
          pub const P_224: EcCurve = 0;
          pub const P_256: EcCurve = 1;
          pub const P_384: EcCurve = 2;
          pub const P_521: EcCurve = 3;
          pub(crate) mod mangled { pub use super::EcCurve as _7_android_8_hardware_7_keymint_7_EcCurve; }
        }
        pub mod ErrorCode {
          #![allow(non_upper_case_globals)]
          pub type ErrorCode = i32;
          pub const OK: ErrorCode = 0;
          pub const ROOT_OF_TRUST_ALREADY_SET: ErrorCode = -1;
          pub const UNSUPPORTED_PURPOSE: ErrorCode = -2;
          pub const INCOMPATIBLE_PURPOSE: ErrorCode = -3;
          pub const UNSUPPORTED_ALGORITHM: ErrorCode = -4;
          pub const INCOMPATIBLE_ALGORITHM: ErrorCode = -5;
          pub const UNSUPPORTED_KEY_SIZE: ErrorCode = -6;
          pub const UNSUPPORTED_BLOCK_MODE: ErrorCode = -7;
          pub const INCOMPATIBLE_BLOCK_MODE: ErrorCode = -8;
          pub const UNSUPPORTED_MAC_LENGTH: ErrorCode = -9;
          pub const UNSUPPORTED_PADDING_MODE: ErrorCode = -10;
          pub const INCOMPATIBLE_PADDING_MODE: ErrorCode = -11;
          pub const UNSUPPORTED_DIGEST: ErrorCode = -12;
          pub const INCOMPATIBLE_DIGEST: ErrorCode = -13;
          pub const INVALID_EXPIRATION_TIME: ErrorCode = -14;
          pub const INVALID_USER_ID: ErrorCode = -15;
          pub const INVALID_AUTHORIZATION_TIMEOUT: ErrorCode = -16;
          pub const UNSUPPORTED_KEY_FORMAT: ErrorCode = -17;
          pub const INCOMPATIBLE_KEY_FORMAT: ErrorCode = -18;
          pub const UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM: ErrorCode = -19;
          pub const UNSUPPORTED_KEY_VERIFICATION_ALGORITHM: ErrorCode = -20;
          pub const INVALID_INPUT_LENGTH: ErrorCode = -21;
          pub const KEY_EXPORT_OPTIONS_INVALID: ErrorCode = -22;
          pub const DELEGATION_NOT_ALLOWED: ErrorCode = -23;
          pub const KEY_NOT_YET_VALID: ErrorCode = -24;
          pub const KEY_EXPIRED: ErrorCode = -25;
          pub const KEY_USER_NOT_AUTHENTICATED: ErrorCode = -26;
          pub const OUTPUT_PARAMETER_NULL: ErrorCode = -27;
          pub const INVALID_OPERATION_HANDLE: ErrorCode = -28;
          pub const INSUFFICIENT_BUFFER_SPACE: ErrorCode = -29;
          pub const VERIFICATION_FAILED: ErrorCode = -30;
          pub const TOO_MANY_OPERATIONS: ErrorCode = -31;
          pub const UNEXPECTED_NULL_POINTER: ErrorCode = -32;
          pub const INVALID_KEY_BLOB: ErrorCode = -33;
          pub const IMPORTED_KEY_NOT_ENCRYPTED: ErrorCode = -34;
          pub const IMPORTED_KEY_DECRYPTION_FAILED: ErrorCode = -35;
          pub const IMPORTED_KEY_NOT_SIGNED: ErrorCode = -36;
          pub const IMPORTED_KEY_VERIFICATION_FAILED: ErrorCode = -37;
          pub const INVALID_ARGUMENT: ErrorCode = -38;
          pub const UNSUPPORTED_TAG: ErrorCode = -39;
          pub const INVALID_TAG: ErrorCode = -40;
          pub const MEMORY_ALLOCATION_FAILED: ErrorCode = -41;
          pub const IMPORT_PARAMETER_MISMATCH: ErrorCode = -44;
          pub const SECURE_HW_ACCESS_DENIED: ErrorCode = -45;
          pub const OPERATION_CANCELLED: ErrorCode = -46;
          pub const CONCURRENT_ACCESS_CONFLICT: ErrorCode = -47;
          pub const SECURE_HW_BUSY: ErrorCode = -48;
          pub const SECURE_HW_COMMUNICATION_FAILED: ErrorCode = -49;
          pub const UNSUPPORTED_EC_FIELD: ErrorCode = -50;
          pub const MISSING_NONCE: ErrorCode = -51;
          pub const INVALID_NONCE: ErrorCode = -52;
          pub const MISSING_MAC_LENGTH: ErrorCode = -53;
          pub const KEY_RATE_LIMIT_EXCEEDED: ErrorCode = -54;
          pub const CALLER_NONCE_PROHIBITED: ErrorCode = -55;
          pub const KEY_MAX_OPS_EXCEEDED: ErrorCode = -56;
          pub const INVALID_MAC_LENGTH: ErrorCode = -57;
          pub const MISSING_MIN_MAC_LENGTH: ErrorCode = -58;
          pub const UNSUPPORTED_MIN_MAC_LENGTH: ErrorCode = -59;
          pub const UNSUPPORTED_KDF: ErrorCode = -60;
          pub const UNSUPPORTED_EC_CURVE: ErrorCode = -61;
          pub const KEY_REQUIRES_UPGRADE: ErrorCode = -62;
          pub const ATTESTATION_CHALLENGE_MISSING: ErrorCode = -63;
          pub const KEYMASTER_NOT_CONFIGURED: ErrorCode = -64;
          pub const ATTESTATION_APPLICATION_ID_MISSING: ErrorCode = -65;
          pub const CANNOT_ATTEST_IDS: ErrorCode = -66;
          pub const ROLLBACK_RESISTANCE_UNAVAILABLE: ErrorCode = -67;
          pub const HARDWARE_TYPE_UNAVAILABLE: ErrorCode = -68;
          pub const PROOF_OF_PRESENCE_REQUIRED: ErrorCode = -69;
          pub const CONCURRENT_PROOF_OF_PRESENCE_REQUESTED: ErrorCode = -70;
          pub const NO_USER_CONFIRMATION: ErrorCode = -71;
          pub const DEVICE_LOCKED: ErrorCode = -72;
          pub const EARLY_BOOT_ENDED: ErrorCode = -73;
          pub const ATTESTATION_KEYS_NOT_PROVISIONED: ErrorCode = -74;
          pub const ATTESTATION_IDS_NOT_PROVISIONED: ErrorCode = -75;
          pub const INVALID_OPERATION: ErrorCode = -76;
          pub const STORAGE_KEY_UNSUPPORTED: ErrorCode = -77;
          pub const UNIMPLEMENTED: ErrorCode = -100;
          pub const VERSION_MISMATCH: ErrorCode = -101;
          pub const UNKNOWN_ERROR: ErrorCode = -1000;
          pub(crate) mod mangled { pub use super::ErrorCode as _7_android_8_hardware_7_keymint_9_ErrorCode; }
        }
        pub mod HardwareAuthToken {
          pub struct HardwareAuthToken {
            pub challenge: i64, 
            pub userId: i64, 
            pub authenticatorId: i64, 
            pub authenticatorType: crate::mangled::_7_android_8_hardware_7_keymint_25_HardwareAuthenticatorType, 
            pub timestamp: crate::mangled::_7_android_8_hardware_7_keymint_9_Timestamp, 
            pub mac: Vec<u8>, 
          }
          pub(crate) mod mangled { pub use super::HardwareAuthToken as _7_android_8_hardware_7_keymint_17_HardwareAuthToken; }
          impl Default for HardwareAuthToken {
            fn default() -> Self {
              Self {
                challenge: 0,
                userId: 0,
                authenticatorId: 0,
                authenticatorType: Default::default(),
                timestamp: Default::default(),
                mac: Default::default(),
              }
            }
          }
          impl binder::parcel::Serialize for HardwareAuthToken {
            fn serialize(&self, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              <Self as binder::parcel::SerializeOption>::serialize_option(Some(self), parcel)
            }
          }
          impl binder::parcel::SerializeArray for HardwareAuthToken {}
          impl binder::parcel::SerializeOption for HardwareAuthToken {
            fn serialize_option(this: Option<&Self>, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              let this = if let Some(this) = this {
                parcel.write(&1i32)?;
                this
              } else {
                return parcel.write(&0i32);
              };
              let start_pos = parcel.get_data_position();
              parcel.write(&0i32)?;
              parcel.write(&this.challenge)?;
              parcel.write(&this.userId)?;
              parcel.write(&this.authenticatorId)?;
              parcel.write(&this.authenticatorType)?;
              parcel.write(&this.timestamp)?;
              parcel.write(&this.mac)?;
              let end_pos = parcel.get_data_position();
              let parcelable_size = (end_pos - start_pos) as i32;
              unsafe { parcel.set_data_position(start_pos)?; }
              parcel.write(&parcelable_size)?;
              unsafe { parcel.set_data_position(end_pos)?; }
              Ok(())
            }
          }
          impl binder::parcel::Deserialize for HardwareAuthToken {
            fn deserialize(parcel: &binder::parcel::Parcel) -> binder::Result<Self> {
              <Self as binder::parcel::DeserializeOption>::deserialize_option(parcel)
                 .transpose()
                 .unwrap_or(Err(binder::StatusCode::UNEXPECTED_NULL))
            }
          }
          impl binder::parcel::DeserializeArray for HardwareAuthToken {}
          impl binder::parcel::DeserializeOption for HardwareAuthToken {
            fn deserialize_option(parcel: &binder::parcel::Parcel) -> binder::Result<Option<Self>> {
              let status: i32 = parcel.read()?;
              if status == 0 { return Ok(None); }
              let start_pos = parcel.get_data_position();
              let parcelable_size: i32 = parcel.read()?;
              if parcelable_size < 0 { return Err(binder::StatusCode::BAD_VALUE); }
              let mut result = Self::default();
              result.challenge = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.userId = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.authenticatorId = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.authenticatorType = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.timestamp = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.mac = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod HardwareAuthenticatorType {
          #![allow(non_upper_case_globals)]
          pub type HardwareAuthenticatorType = i32;
          pub const NONE: HardwareAuthenticatorType = 0;
          pub const PASSWORD: HardwareAuthenticatorType = 1;
          pub const FINGERPRINT: HardwareAuthenticatorType = 2;
          pub const ANY: HardwareAuthenticatorType = -1;
          pub(crate) mod mangled { pub use super::HardwareAuthenticatorType as _7_android_8_hardware_7_keymint_25_HardwareAuthenticatorType; }
        }
        pub mod HmacSharingParameters {
          pub struct HmacSharingParameters {
            pub seed: Vec<u8>, 
            pub nonce: Vec<u8>, 
          }
          pub(crate) mod mangled { pub use super::HmacSharingParameters as _7_android_8_hardware_7_keymint_21_HmacSharingParameters; }
          impl Default for HmacSharingParameters {
            fn default() -> Self {
              Self {
                seed: Default::default(),
                nonce: Default::default(),
              }
            }
          }
          impl binder::parcel::Serialize for HmacSharingParameters {
            fn serialize(&self, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              <Self as binder::parcel::SerializeOption>::serialize_option(Some(self), parcel)
            }
          }
          impl binder::parcel::SerializeArray for HmacSharingParameters {}
          impl binder::parcel::SerializeOption for HmacSharingParameters {
            fn serialize_option(this: Option<&Self>, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              let this = if let Some(this) = this {
                parcel.write(&1i32)?;
                this
              } else {
                return parcel.write(&0i32);
              };
              let start_pos = parcel.get_data_position();
              parcel.write(&0i32)?;
              parcel.write(&this.seed)?;
              parcel.write(&this.nonce)?;
              let end_pos = parcel.get_data_position();
              let parcelable_size = (end_pos - start_pos) as i32;
              unsafe { parcel.set_data_position(start_pos)?; }
              parcel.write(&parcelable_size)?;
              unsafe { parcel.set_data_position(end_pos)?; }
              Ok(())
            }
          }
          impl binder::parcel::Deserialize for HmacSharingParameters {
            fn deserialize(parcel: &binder::parcel::Parcel) -> binder::Result<Self> {
              <Self as binder::parcel::DeserializeOption>::deserialize_option(parcel)
                 .transpose()
                 .unwrap_or(Err(binder::StatusCode::UNEXPECTED_NULL))
            }
          }
          impl binder::parcel::DeserializeArray for HmacSharingParameters {}
          impl binder::parcel::DeserializeOption for HmacSharingParameters {
            fn deserialize_option(parcel: &binder::parcel::Parcel) -> binder::Result<Option<Self>> {
              let status: i32 = parcel.read()?;
              if status == 0 { return Ok(None); }
              let start_pos = parcel.get_data_position();
              let parcelable_size: i32 = parcel.read()?;
              if parcelable_size < 0 { return Err(binder::StatusCode::BAD_VALUE); }
              let mut result = Self::default();
              result.seed = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.nonce = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod IKeyMintDevice {
          #![allow(non_upper_case_globals)]
          #![allow(non_snake_case)]
          #[allow(unused_imports)] use binder::IBinder;
          use binder::declare_binder_interface;
          declare_binder_interface! {
            IKeyMintDevice["android.hardware.keymint.IKeyMintDevice"] {
              native: BnKeyMintDevice(on_transact),
              proxy: BpKeyMintDevice {
              },
            }
          }
          pub trait IKeyMintDevice: binder::Interface {
            fn get_descriptor() -> &'static str where Self: Sized { "android.hardware.keymint.IKeyMintDevice" }
            fn getHardwareInfo(&self) -> binder::public_api::Result<crate::mangled::_7_android_8_hardware_7_keymint_19_KeyMintHardwareInfo> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn verifyAuthorization(&self, _arg_challenge: i64, _arg_parametersToVerify: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_token: &crate::mangled::_7_android_8_hardware_7_keymint_17_HardwareAuthToken) -> binder::public_api::Result<crate::mangled::_7_android_8_hardware_7_keymint_17_VerificationToken> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn addRngEntropy(&self, _arg_data: &[u8]) -> binder::public_api::Result<()> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn generateKey(&self, _arg_keyParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_generatedKeyBlob: &mut Vec<u8>, _arg_generatedKeyCharacteristics: &mut crate::mangled::_7_android_8_hardware_7_keymint_18_KeyCharacteristics, _arg_outCertChain: &mut Vec<crate::mangled::_7_android_8_hardware_7_keymint_11_Certificate>) -> binder::public_api::Result<()> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn importKey(&self, _arg_inKeyParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_inKeyFormat: crate::mangled::_7_android_8_hardware_7_keymint_9_KeyFormat, _arg_inKeyData: &[u8], _arg_outImportedKeyBlob: &mut Vec<u8>, _arg_outImportedKeyCharacteristics: &mut crate::mangled::_7_android_8_hardware_7_keymint_18_KeyCharacteristics, _arg_outCertChain: &mut Vec<crate::mangled::_7_android_8_hardware_7_keymint_11_Certificate>) -> binder::public_api::Result<()> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn importWrappedKey(&self, _arg_inWrappedKeyData: &[u8], _arg_inWrappingKeyBlob: &[u8], _arg_inMaskingKey: &[u8], _arg_inUnwrappingParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_inPasswordSid: i64, _arg_inBiometricSid: i64, _arg_outImportedKeyBlob: &mut Vec<u8>, _arg_outImportedKeyCharacteristics: &mut crate::mangled::_7_android_8_hardware_7_keymint_18_KeyCharacteristics) -> binder::public_api::Result<()> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn upgradeKey(&self, _arg_inKeyBlobToUpgrade: &[u8], _arg_inUpgradeParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter]) -> binder::public_api::Result<Vec<u8>> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn deleteKey(&self, _arg_inKeyBlob: &[u8]) -> binder::public_api::Result<()> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn deleteAllKeys(&self) -> binder::public_api::Result<()> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn destroyAttestationIds(&self) -> binder::public_api::Result<()> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn begin(&self, _arg_inPurpose: crate::mangled::_7_android_8_hardware_7_keymint_10_KeyPurpose, _arg_inKeyBlob: &[u8], _arg_inParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_inAuthToken: &crate::mangled::_7_android_8_hardware_7_keymint_17_HardwareAuthToken) -> binder::public_api::Result<crate::mangled::_7_android_8_hardware_7_keymint_11_BeginResult> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn getDefaultImpl() -> DefaultImpl where Self: Sized {
              DEFAULT_IMPL.lock().unwrap().clone()
            }
            fn setDefaultImpl(d: DefaultImpl) -> DefaultImpl where Self: Sized {
              std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
            }
          }
          pub const TRANSACTION_getHardwareInfo: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 0;
          pub const TRANSACTION_verifyAuthorization: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 1;
          pub const TRANSACTION_addRngEntropy: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 2;
          pub const TRANSACTION_generateKey: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 3;
          pub const TRANSACTION_importKey: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 4;
          pub const TRANSACTION_importWrappedKey: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 5;
          pub const TRANSACTION_upgradeKey: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 6;
          pub const TRANSACTION_deleteKey: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 7;
          pub const TRANSACTION_deleteAllKeys: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 8;
          pub const TRANSACTION_destroyAttestationIds: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 9;
          pub const TRANSACTION_begin: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 10;
          pub type DefaultImpl = Option<std::sync::Arc<dyn IKeyMintDevice + Send + Sync>>;
          use lazy_static::lazy_static;
          lazy_static! {
            static ref DEFAULT_IMPL: std::sync::Mutex<DefaultImpl> = std::sync::Mutex::new(None);
          }
          pub(crate) mod mangled { pub use super::IKeyMintDevice as _7_android_8_hardware_7_keymint_14_IKeyMintDevice; }
          impl IKeyMintDevice for BpKeyMintDevice {
            fn getHardwareInfo(&self) -> binder::public_api::Result<crate::mangled::_7_android_8_hardware_7_keymint_19_KeyMintHardwareInfo> {
              let _aidl_reply = self.binder.transact(TRANSACTION_getHardwareInfo, 0, |_aidl_data| {
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeyMintDevice>::getDefaultImpl() {
                  return _aidl_default_impl.getHardwareInfo();
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: crate::mangled::_7_android_8_hardware_7_keymint_19_KeyMintHardwareInfo = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
            fn verifyAuthorization(&self, _arg_challenge: i64, _arg_parametersToVerify: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_token: &crate::mangled::_7_android_8_hardware_7_keymint_17_HardwareAuthToken) -> binder::public_api::Result<crate::mangled::_7_android_8_hardware_7_keymint_17_VerificationToken> {
              let _aidl_reply = self.binder.transact(TRANSACTION_verifyAuthorization, 0, |_aidl_data| {
                _aidl_data.write(&_arg_challenge)?;
                _aidl_data.write(_arg_parametersToVerify)?;
                _aidl_data.write(_arg_token)?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeyMintDevice>::getDefaultImpl() {
                  return _aidl_default_impl.verifyAuthorization(_arg_challenge, _arg_parametersToVerify, _arg_token);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: crate::mangled::_7_android_8_hardware_7_keymint_17_VerificationToken = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
            fn addRngEntropy(&self, _arg_data: &[u8]) -> binder::public_api::Result<()> {
              let _aidl_reply = self.binder.transact(TRANSACTION_addRngEntropy, 0, |_aidl_data| {
                _aidl_data.write(_arg_data)?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeyMintDevice>::getDefaultImpl() {
                  return _aidl_default_impl.addRngEntropy(_arg_data);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              Ok(())
            }
            fn generateKey(&self, _arg_keyParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_generatedKeyBlob: &mut Vec<u8>, _arg_generatedKeyCharacteristics: &mut crate::mangled::_7_android_8_hardware_7_keymint_18_KeyCharacteristics, _arg_outCertChain: &mut Vec<crate::mangled::_7_android_8_hardware_7_keymint_11_Certificate>) -> binder::public_api::Result<()> {
              let _aidl_reply = self.binder.transact(TRANSACTION_generateKey, 0, |_aidl_data| {
                _aidl_data.write(_arg_keyParams)?;
                _aidl_data.write_slice_size(Some(_arg_generatedKeyBlob))?;
                _aidl_data.write_slice_size(Some(_arg_outCertChain))?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeyMintDevice>::getDefaultImpl() {
                  return _aidl_default_impl.generateKey(_arg_keyParams, _arg_generatedKeyBlob, _arg_generatedKeyCharacteristics, _arg_outCertChain);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              *_arg_generatedKeyBlob = _aidl_reply.read()?;
              *_arg_generatedKeyCharacteristics = _aidl_reply.read()?;
              *_arg_outCertChain = _aidl_reply.read()?;
              Ok(())
            }
            fn importKey(&self, _arg_inKeyParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_inKeyFormat: crate::mangled::_7_android_8_hardware_7_keymint_9_KeyFormat, _arg_inKeyData: &[u8], _arg_outImportedKeyBlob: &mut Vec<u8>, _arg_outImportedKeyCharacteristics: &mut crate::mangled::_7_android_8_hardware_7_keymint_18_KeyCharacteristics, _arg_outCertChain: &mut Vec<crate::mangled::_7_android_8_hardware_7_keymint_11_Certificate>) -> binder::public_api::Result<()> {
              let _aidl_reply = self.binder.transact(TRANSACTION_importKey, 0, |_aidl_data| {
                _aidl_data.write(_arg_inKeyParams)?;
                _aidl_data.write(&_arg_inKeyFormat)?;
                _aidl_data.write(_arg_inKeyData)?;
                _aidl_data.write_slice_size(Some(_arg_outImportedKeyBlob))?;
                _aidl_data.write_slice_size(Some(_arg_outCertChain))?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeyMintDevice>::getDefaultImpl() {
                  return _aidl_default_impl.importKey(_arg_inKeyParams, _arg_inKeyFormat, _arg_inKeyData, _arg_outImportedKeyBlob, _arg_outImportedKeyCharacteristics, _arg_outCertChain);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              *_arg_outImportedKeyBlob = _aidl_reply.read()?;
              *_arg_outImportedKeyCharacteristics = _aidl_reply.read()?;
              *_arg_outCertChain = _aidl_reply.read()?;
              Ok(())
            }
            fn importWrappedKey(&self, _arg_inWrappedKeyData: &[u8], _arg_inWrappingKeyBlob: &[u8], _arg_inMaskingKey: &[u8], _arg_inUnwrappingParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_inPasswordSid: i64, _arg_inBiometricSid: i64, _arg_outImportedKeyBlob: &mut Vec<u8>, _arg_outImportedKeyCharacteristics: &mut crate::mangled::_7_android_8_hardware_7_keymint_18_KeyCharacteristics) -> binder::public_api::Result<()> {
              let _aidl_reply = self.binder.transact(TRANSACTION_importWrappedKey, 0, |_aidl_data| {
                _aidl_data.write(_arg_inWrappedKeyData)?;
                _aidl_data.write(_arg_inWrappingKeyBlob)?;
                _aidl_data.write(_arg_inMaskingKey)?;
                _aidl_data.write(_arg_inUnwrappingParams)?;
                _aidl_data.write(&_arg_inPasswordSid)?;
                _aidl_data.write(&_arg_inBiometricSid)?;
                _aidl_data.write_slice_size(Some(_arg_outImportedKeyBlob))?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeyMintDevice>::getDefaultImpl() {
                  return _aidl_default_impl.importWrappedKey(_arg_inWrappedKeyData, _arg_inWrappingKeyBlob, _arg_inMaskingKey, _arg_inUnwrappingParams, _arg_inPasswordSid, _arg_inBiometricSid, _arg_outImportedKeyBlob, _arg_outImportedKeyCharacteristics);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              *_arg_outImportedKeyBlob = _aidl_reply.read()?;
              *_arg_outImportedKeyCharacteristics = _aidl_reply.read()?;
              Ok(())
            }
            fn upgradeKey(&self, _arg_inKeyBlobToUpgrade: &[u8], _arg_inUpgradeParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter]) -> binder::public_api::Result<Vec<u8>> {
              let _aidl_reply = self.binder.transact(TRANSACTION_upgradeKey, 0, |_aidl_data| {
                _aidl_data.write(_arg_inKeyBlobToUpgrade)?;
                _aidl_data.write(_arg_inUpgradeParams)?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeyMintDevice>::getDefaultImpl() {
                  return _aidl_default_impl.upgradeKey(_arg_inKeyBlobToUpgrade, _arg_inUpgradeParams);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: Vec<u8> = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
            fn deleteKey(&self, _arg_inKeyBlob: &[u8]) -> binder::public_api::Result<()> {
              let _aidl_reply = self.binder.transact(TRANSACTION_deleteKey, 0, |_aidl_data| {
                _aidl_data.write(_arg_inKeyBlob)?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeyMintDevice>::getDefaultImpl() {
                  return _aidl_default_impl.deleteKey(_arg_inKeyBlob);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              Ok(())
            }
            fn deleteAllKeys(&self) -> binder::public_api::Result<()> {
              let _aidl_reply = self.binder.transact(TRANSACTION_deleteAllKeys, 0, |_aidl_data| {
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeyMintDevice>::getDefaultImpl() {
                  return _aidl_default_impl.deleteAllKeys();
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              Ok(())
            }
            fn destroyAttestationIds(&self) -> binder::public_api::Result<()> {
              let _aidl_reply = self.binder.transact(TRANSACTION_destroyAttestationIds, 0, |_aidl_data| {
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeyMintDevice>::getDefaultImpl() {
                  return _aidl_default_impl.destroyAttestationIds();
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              Ok(())
            }
            fn begin(&self, _arg_inPurpose: crate::mangled::_7_android_8_hardware_7_keymint_10_KeyPurpose, _arg_inKeyBlob: &[u8], _arg_inParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_inAuthToken: &crate::mangled::_7_android_8_hardware_7_keymint_17_HardwareAuthToken) -> binder::public_api::Result<crate::mangled::_7_android_8_hardware_7_keymint_11_BeginResult> {
              let _aidl_reply = self.binder.transact(TRANSACTION_begin, 0, |_aidl_data| {
                _aidl_data.write(&_arg_inPurpose)?;
                _aidl_data.write(_arg_inKeyBlob)?;
                _aidl_data.write(_arg_inParams)?;
                _aidl_data.write(_arg_inAuthToken)?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeyMintDevice>::getDefaultImpl() {
                  return _aidl_default_impl.begin(_arg_inPurpose, _arg_inKeyBlob, _arg_inParams, _arg_inAuthToken);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: crate::mangled::_7_android_8_hardware_7_keymint_11_BeginResult = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
          }
          impl IKeyMintDevice for binder::Binder<BnKeyMintDevice> {
            fn getHardwareInfo(&self) -> binder::public_api::Result<crate::mangled::_7_android_8_hardware_7_keymint_19_KeyMintHardwareInfo> { self.0.getHardwareInfo() }
            fn verifyAuthorization(&self, _arg_challenge: i64, _arg_parametersToVerify: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_token: &crate::mangled::_7_android_8_hardware_7_keymint_17_HardwareAuthToken) -> binder::public_api::Result<crate::mangled::_7_android_8_hardware_7_keymint_17_VerificationToken> { self.0.verifyAuthorization(_arg_challenge, _arg_parametersToVerify, _arg_token) }
            fn addRngEntropy(&self, _arg_data: &[u8]) -> binder::public_api::Result<()> { self.0.addRngEntropy(_arg_data) }
            fn generateKey(&self, _arg_keyParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_generatedKeyBlob: &mut Vec<u8>, _arg_generatedKeyCharacteristics: &mut crate::mangled::_7_android_8_hardware_7_keymint_18_KeyCharacteristics, _arg_outCertChain: &mut Vec<crate::mangled::_7_android_8_hardware_7_keymint_11_Certificate>) -> binder::public_api::Result<()> { self.0.generateKey(_arg_keyParams, _arg_generatedKeyBlob, _arg_generatedKeyCharacteristics, _arg_outCertChain) }
            fn importKey(&self, _arg_inKeyParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_inKeyFormat: crate::mangled::_7_android_8_hardware_7_keymint_9_KeyFormat, _arg_inKeyData: &[u8], _arg_outImportedKeyBlob: &mut Vec<u8>, _arg_outImportedKeyCharacteristics: &mut crate::mangled::_7_android_8_hardware_7_keymint_18_KeyCharacteristics, _arg_outCertChain: &mut Vec<crate::mangled::_7_android_8_hardware_7_keymint_11_Certificate>) -> binder::public_api::Result<()> { self.0.importKey(_arg_inKeyParams, _arg_inKeyFormat, _arg_inKeyData, _arg_outImportedKeyBlob, _arg_outImportedKeyCharacteristics, _arg_outCertChain) }
            fn importWrappedKey(&self, _arg_inWrappedKeyData: &[u8], _arg_inWrappingKeyBlob: &[u8], _arg_inMaskingKey: &[u8], _arg_inUnwrappingParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_inPasswordSid: i64, _arg_inBiometricSid: i64, _arg_outImportedKeyBlob: &mut Vec<u8>, _arg_outImportedKeyCharacteristics: &mut crate::mangled::_7_android_8_hardware_7_keymint_18_KeyCharacteristics) -> binder::public_api::Result<()> { self.0.importWrappedKey(_arg_inWrappedKeyData, _arg_inWrappingKeyBlob, _arg_inMaskingKey, _arg_inUnwrappingParams, _arg_inPasswordSid, _arg_inBiometricSid, _arg_outImportedKeyBlob, _arg_outImportedKeyCharacteristics) }
            fn upgradeKey(&self, _arg_inKeyBlobToUpgrade: &[u8], _arg_inUpgradeParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter]) -> binder::public_api::Result<Vec<u8>> { self.0.upgradeKey(_arg_inKeyBlobToUpgrade, _arg_inUpgradeParams) }
            fn deleteKey(&self, _arg_inKeyBlob: &[u8]) -> binder::public_api::Result<()> { self.0.deleteKey(_arg_inKeyBlob) }
            fn deleteAllKeys(&self) -> binder::public_api::Result<()> { self.0.deleteAllKeys() }
            fn destroyAttestationIds(&self) -> binder::public_api::Result<()> { self.0.destroyAttestationIds() }
            fn begin(&self, _arg_inPurpose: crate::mangled::_7_android_8_hardware_7_keymint_10_KeyPurpose, _arg_inKeyBlob: &[u8], _arg_inParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_inAuthToken: &crate::mangled::_7_android_8_hardware_7_keymint_17_HardwareAuthToken) -> binder::public_api::Result<crate::mangled::_7_android_8_hardware_7_keymint_11_BeginResult> { self.0.begin(_arg_inPurpose, _arg_inKeyBlob, _arg_inParams, _arg_inAuthToken) }
          }
          fn on_transact(_aidl_service: &dyn IKeyMintDevice, _aidl_code: binder::TransactionCode, _aidl_data: &binder::parcel::Parcel, _aidl_reply: &mut binder::parcel::Parcel) -> binder::Result<()> {
            match _aidl_code {
              TRANSACTION_getHardwareInfo => {
                let _aidl_return = _aidl_service.getHardwareInfo();
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_verifyAuthorization => {
                let _arg_challenge: i64 = _aidl_data.read()?;
                let _arg_parametersToVerify: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter> = _aidl_data.read()?;
                let _arg_token: crate::mangled::_7_android_8_hardware_7_keymint_17_HardwareAuthToken = _aidl_data.read()?;
                let _aidl_return = _aidl_service.verifyAuthorization(_arg_challenge, &_arg_parametersToVerify, &_arg_token);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_addRngEntropy => {
                let _arg_data: Vec<u8> = _aidl_data.read()?;
                let _aidl_return = _aidl_service.addRngEntropy(&_arg_data);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_generateKey => {
                let _arg_keyParams: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter> = _aidl_data.read()?;
                let mut _arg_generatedKeyBlob: Vec<u8> = Default::default();
                _aidl_data.resize_out_vec(&mut _arg_generatedKeyBlob)?;
                let mut _arg_generatedKeyCharacteristics: crate::mangled::_7_android_8_hardware_7_keymint_18_KeyCharacteristics = Default::default();
                let mut _arg_outCertChain: Vec<crate::mangled::_7_android_8_hardware_7_keymint_11_Certificate> = Default::default();
                _aidl_data.resize_out_vec(&mut _arg_outCertChain)?;
                let _aidl_return = _aidl_service.generateKey(&_arg_keyParams, &mut _arg_generatedKeyBlob, &mut _arg_generatedKeyCharacteristics, &mut _arg_outCertChain);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(&_arg_generatedKeyBlob)?;
                    _aidl_reply.write(&_arg_generatedKeyCharacteristics)?;
                    _aidl_reply.write(&_arg_outCertChain)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_importKey => {
                let _arg_inKeyParams: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter> = _aidl_data.read()?;
                let _arg_inKeyFormat: crate::mangled::_7_android_8_hardware_7_keymint_9_KeyFormat = _aidl_data.read()?;
                let _arg_inKeyData: Vec<u8> = _aidl_data.read()?;
                let mut _arg_outImportedKeyBlob: Vec<u8> = Default::default();
                _aidl_data.resize_out_vec(&mut _arg_outImportedKeyBlob)?;
                let mut _arg_outImportedKeyCharacteristics: crate::mangled::_7_android_8_hardware_7_keymint_18_KeyCharacteristics = Default::default();
                let mut _arg_outCertChain: Vec<crate::mangled::_7_android_8_hardware_7_keymint_11_Certificate> = Default::default();
                _aidl_data.resize_out_vec(&mut _arg_outCertChain)?;
                let _aidl_return = _aidl_service.importKey(&_arg_inKeyParams, _arg_inKeyFormat, &_arg_inKeyData, &mut _arg_outImportedKeyBlob, &mut _arg_outImportedKeyCharacteristics, &mut _arg_outCertChain);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(&_arg_outImportedKeyBlob)?;
                    _aidl_reply.write(&_arg_outImportedKeyCharacteristics)?;
                    _aidl_reply.write(&_arg_outCertChain)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_importWrappedKey => {
                let _arg_inWrappedKeyData: Vec<u8> = _aidl_data.read()?;
                let _arg_inWrappingKeyBlob: Vec<u8> = _aidl_data.read()?;
                let _arg_inMaskingKey: Vec<u8> = _aidl_data.read()?;
                let _arg_inUnwrappingParams: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter> = _aidl_data.read()?;
                let _arg_inPasswordSid: i64 = _aidl_data.read()?;
                let _arg_inBiometricSid: i64 = _aidl_data.read()?;
                let mut _arg_outImportedKeyBlob: Vec<u8> = Default::default();
                _aidl_data.resize_out_vec(&mut _arg_outImportedKeyBlob)?;
                let mut _arg_outImportedKeyCharacteristics: crate::mangled::_7_android_8_hardware_7_keymint_18_KeyCharacteristics = Default::default();
                let _aidl_return = _aidl_service.importWrappedKey(&_arg_inWrappedKeyData, &_arg_inWrappingKeyBlob, &_arg_inMaskingKey, &_arg_inUnwrappingParams, _arg_inPasswordSid, _arg_inBiometricSid, &mut _arg_outImportedKeyBlob, &mut _arg_outImportedKeyCharacteristics);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(&_arg_outImportedKeyBlob)?;
                    _aidl_reply.write(&_arg_outImportedKeyCharacteristics)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_upgradeKey => {
                let _arg_inKeyBlobToUpgrade: Vec<u8> = _aidl_data.read()?;
                let _arg_inUpgradeParams: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter> = _aidl_data.read()?;
                let _aidl_return = _aidl_service.upgradeKey(&_arg_inKeyBlobToUpgrade, &_arg_inUpgradeParams);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_deleteKey => {
                let _arg_inKeyBlob: Vec<u8> = _aidl_data.read()?;
                let _aidl_return = _aidl_service.deleteKey(&_arg_inKeyBlob);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_deleteAllKeys => {
                let _aidl_return = _aidl_service.deleteAllKeys();
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_destroyAttestationIds => {
                let _aidl_return = _aidl_service.destroyAttestationIds();
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_begin => {
                let _arg_inPurpose: crate::mangled::_7_android_8_hardware_7_keymint_10_KeyPurpose = _aidl_data.read()?;
                let _arg_inKeyBlob: Vec<u8> = _aidl_data.read()?;
                let _arg_inParams: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter> = _aidl_data.read()?;
                let _arg_inAuthToken: crate::mangled::_7_android_8_hardware_7_keymint_17_HardwareAuthToken = _aidl_data.read()?;
                let _aidl_return = _aidl_service.begin(_arg_inPurpose, &_arg_inKeyBlob, &_arg_inParams, &_arg_inAuthToken);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              _ => Err(binder::StatusCode::UNKNOWN_TRANSACTION)
            }
          }
        }
        pub mod IKeyMintOperation {
          #![allow(non_upper_case_globals)]
          #![allow(non_snake_case)]
          #[allow(unused_imports)] use binder::IBinder;
          use binder::declare_binder_interface;
          declare_binder_interface! {
            IKeyMintOperation["android.hardware.keymint.IKeyMintOperation"] {
              native: BnKeyMintOperation(on_transact),
              proxy: BpKeyMintOperation {
              },
            }
          }
          pub trait IKeyMintOperation: binder::Interface {
            fn get_descriptor() -> &'static str where Self: Sized { "android.hardware.keymint.IKeyMintOperation" }
            fn update(&self, _arg_inParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_input: &[u8], _arg_inVerificationToken: &crate::mangled::_7_android_8_hardware_7_keymint_17_VerificationToken, _arg_outParams: &mut Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter>, _arg_output: &mut Vec<u8>) -> binder::public_api::Result<i32> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn finish(&self, _arg_inParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_input: &[u8], _arg_inSignature: &[u8], _arg_authToken: &crate::mangled::_7_android_8_hardware_7_keymint_17_HardwareAuthToken, _arg_inVerificationToken: &crate::mangled::_7_android_8_hardware_7_keymint_17_VerificationToken, _arg_outParams: &mut Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter>, _arg_output: &mut Vec<u8>) -> binder::public_api::Result<()> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn abort(&self) -> binder::public_api::Result<()> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn getDefaultImpl() -> DefaultImpl where Self: Sized {
              DEFAULT_IMPL.lock().unwrap().clone()
            }
            fn setDefaultImpl(d: DefaultImpl) -> DefaultImpl where Self: Sized {
              std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
            }
          }
          pub const TRANSACTION_update: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 0;
          pub const TRANSACTION_finish: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 1;
          pub const TRANSACTION_abort: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 2;
          pub type DefaultImpl = Option<std::sync::Arc<dyn IKeyMintOperation + Send + Sync>>;
          use lazy_static::lazy_static;
          lazy_static! {
            static ref DEFAULT_IMPL: std::sync::Mutex<DefaultImpl> = std::sync::Mutex::new(None);
          }
          pub(crate) mod mangled { pub use super::IKeyMintOperation as _7_android_8_hardware_7_keymint_17_IKeyMintOperation; }
          impl IKeyMintOperation for BpKeyMintOperation {
            fn update(&self, _arg_inParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_input: &[u8], _arg_inVerificationToken: &crate::mangled::_7_android_8_hardware_7_keymint_17_VerificationToken, _arg_outParams: &mut Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter>, _arg_output: &mut Vec<u8>) -> binder::public_api::Result<i32> {
              let _aidl_reply = self.binder.transact(TRANSACTION_update, 0, |_aidl_data| {
                _aidl_data.write(_arg_inParams)?;
                _aidl_data.write(_arg_input)?;
                _aidl_data.write(_arg_inVerificationToken)?;
                _aidl_data.write_slice_size(Some(_arg_outParams))?;
                _aidl_data.write_slice_size(Some(_arg_output))?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeyMintOperation>::getDefaultImpl() {
                  return _aidl_default_impl.update(_arg_inParams, _arg_input, _arg_inVerificationToken, _arg_outParams, _arg_output);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: i32 = _aidl_reply.read()?;
              *_arg_outParams = _aidl_reply.read()?;
              *_arg_output = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
            fn finish(&self, _arg_inParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_input: &[u8], _arg_inSignature: &[u8], _arg_authToken: &crate::mangled::_7_android_8_hardware_7_keymint_17_HardwareAuthToken, _arg_inVerificationToken: &crate::mangled::_7_android_8_hardware_7_keymint_17_VerificationToken, _arg_outParams: &mut Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter>, _arg_output: &mut Vec<u8>) -> binder::public_api::Result<()> {
              let _aidl_reply = self.binder.transact(TRANSACTION_finish, 0, |_aidl_data| {
                _aidl_data.write(_arg_inParams)?;
                _aidl_data.write(_arg_input)?;
                _aidl_data.write(_arg_inSignature)?;
                _aidl_data.write(_arg_authToken)?;
                _aidl_data.write(_arg_inVerificationToken)?;
                _aidl_data.write_slice_size(Some(_arg_outParams))?;
                _aidl_data.write_slice_size(Some(_arg_output))?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeyMintOperation>::getDefaultImpl() {
                  return _aidl_default_impl.finish(_arg_inParams, _arg_input, _arg_inSignature, _arg_authToken, _arg_inVerificationToken, _arg_outParams, _arg_output);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              *_arg_outParams = _aidl_reply.read()?;
              *_arg_output = _aidl_reply.read()?;
              Ok(())
            }
            fn abort(&self) -> binder::public_api::Result<()> {
              let _aidl_reply = self.binder.transact(TRANSACTION_abort, 0, |_aidl_data| {
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeyMintOperation>::getDefaultImpl() {
                  return _aidl_default_impl.abort();
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              Ok(())
            }
          }
          impl IKeyMintOperation for binder::Binder<BnKeyMintOperation> {
            fn update(&self, _arg_inParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_input: &[u8], _arg_inVerificationToken: &crate::mangled::_7_android_8_hardware_7_keymint_17_VerificationToken, _arg_outParams: &mut Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter>, _arg_output: &mut Vec<u8>) -> binder::public_api::Result<i32> { self.0.update(_arg_inParams, _arg_input, _arg_inVerificationToken, _arg_outParams, _arg_output) }
            fn finish(&self, _arg_inParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_input: &[u8], _arg_inSignature: &[u8], _arg_authToken: &crate::mangled::_7_android_8_hardware_7_keymint_17_HardwareAuthToken, _arg_inVerificationToken: &crate::mangled::_7_android_8_hardware_7_keymint_17_VerificationToken, _arg_outParams: &mut Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter>, _arg_output: &mut Vec<u8>) -> binder::public_api::Result<()> { self.0.finish(_arg_inParams, _arg_input, _arg_inSignature, _arg_authToken, _arg_inVerificationToken, _arg_outParams, _arg_output) }
            fn abort(&self) -> binder::public_api::Result<()> { self.0.abort() }
          }
          fn on_transact(_aidl_service: &dyn IKeyMintOperation, _aidl_code: binder::TransactionCode, _aidl_data: &binder::parcel::Parcel, _aidl_reply: &mut binder::parcel::Parcel) -> binder::Result<()> {
            match _aidl_code {
              TRANSACTION_update => {
                let _arg_inParams: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter> = _aidl_data.read()?;
                let _arg_input: Vec<u8> = _aidl_data.read()?;
                let _arg_inVerificationToken: crate::mangled::_7_android_8_hardware_7_keymint_17_VerificationToken = _aidl_data.read()?;
                let mut _arg_outParams: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter> = Default::default();
                _aidl_data.resize_out_vec(&mut _arg_outParams)?;
                let mut _arg_output: Vec<u8> = Default::default();
                _aidl_data.resize_out_vec(&mut _arg_output)?;
                let _aidl_return = _aidl_service.update(&_arg_inParams, &_arg_input, &_arg_inVerificationToken, &mut _arg_outParams, &mut _arg_output);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
                    _aidl_reply.write(&_arg_outParams)?;
                    _aidl_reply.write(&_arg_output)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_finish => {
                let _arg_inParams: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter> = _aidl_data.read()?;
                let _arg_input: Vec<u8> = _aidl_data.read()?;
                let _arg_inSignature: Vec<u8> = _aidl_data.read()?;
                let _arg_authToken: crate::mangled::_7_android_8_hardware_7_keymint_17_HardwareAuthToken = _aidl_data.read()?;
                let _arg_inVerificationToken: crate::mangled::_7_android_8_hardware_7_keymint_17_VerificationToken = _aidl_data.read()?;
                let mut _arg_outParams: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter> = Default::default();
                _aidl_data.resize_out_vec(&mut _arg_outParams)?;
                let mut _arg_output: Vec<u8> = Default::default();
                _aidl_data.resize_out_vec(&mut _arg_output)?;
                let _aidl_return = _aidl_service.finish(&_arg_inParams, &_arg_input, &_arg_inSignature, &_arg_authToken, &_arg_inVerificationToken, &mut _arg_outParams, &mut _arg_output);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(&_arg_outParams)?;
                    _aidl_reply.write(&_arg_output)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_abort => {
                let _aidl_return = _aidl_service.abort();
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              _ => Err(binder::StatusCode::UNKNOWN_TRANSACTION)
            }
          }
        }
        pub mod KeyCharacteristics {
          pub struct KeyCharacteristics {
            pub softwareEnforced: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter>, 
            pub hardwareEnforced: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter>, 
          }
          pub(crate) mod mangled { pub use super::KeyCharacteristics as _7_android_8_hardware_7_keymint_18_KeyCharacteristics; }
          impl Default for KeyCharacteristics {
            fn default() -> Self {
              Self {
                softwareEnforced: Default::default(),
                hardwareEnforced: Default::default(),
              }
            }
          }
          impl binder::parcel::Serialize for KeyCharacteristics {
            fn serialize(&self, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              <Self as binder::parcel::SerializeOption>::serialize_option(Some(self), parcel)
            }
          }
          impl binder::parcel::SerializeArray for KeyCharacteristics {}
          impl binder::parcel::SerializeOption for KeyCharacteristics {
            fn serialize_option(this: Option<&Self>, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              let this = if let Some(this) = this {
                parcel.write(&1i32)?;
                this
              } else {
                return parcel.write(&0i32);
              };
              let start_pos = parcel.get_data_position();
              parcel.write(&0i32)?;
              parcel.write(&this.softwareEnforced)?;
              parcel.write(&this.hardwareEnforced)?;
              let end_pos = parcel.get_data_position();
              let parcelable_size = (end_pos - start_pos) as i32;
              unsafe { parcel.set_data_position(start_pos)?; }
              parcel.write(&parcelable_size)?;
              unsafe { parcel.set_data_position(end_pos)?; }
              Ok(())
            }
          }
          impl binder::parcel::Deserialize for KeyCharacteristics {
            fn deserialize(parcel: &binder::parcel::Parcel) -> binder::Result<Self> {
              <Self as binder::parcel::DeserializeOption>::deserialize_option(parcel)
                 .transpose()
                 .unwrap_or(Err(binder::StatusCode::UNEXPECTED_NULL))
            }
          }
          impl binder::parcel::DeserializeArray for KeyCharacteristics {}
          impl binder::parcel::DeserializeOption for KeyCharacteristics {
            fn deserialize_option(parcel: &binder::parcel::Parcel) -> binder::Result<Option<Self>> {
              let status: i32 = parcel.read()?;
              if status == 0 { return Ok(None); }
              let start_pos = parcel.get_data_position();
              let parcelable_size: i32 = parcel.read()?;
              if parcelable_size < 0 { return Err(binder::StatusCode::BAD_VALUE); }
              let mut result = Self::default();
              result.softwareEnforced = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.hardwareEnforced = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod KeyDerivationFunction {
          #![allow(non_upper_case_globals)]
          pub type KeyDerivationFunction = i32;
          pub const NONE: KeyDerivationFunction = 0;
          pub const RFC5869_SHA256: KeyDerivationFunction = 1;
          pub const ISO18033_2_KDF1_SHA1: KeyDerivationFunction = 2;
          pub const ISO18033_2_KDF1_SHA256: KeyDerivationFunction = 3;
          pub const ISO18033_2_KDF2_SHA1: KeyDerivationFunction = 4;
          pub const ISO18033_2_KDF2_SHA256: KeyDerivationFunction = 5;
          pub(crate) mod mangled { pub use super::KeyDerivationFunction as _7_android_8_hardware_7_keymint_21_KeyDerivationFunction; }
        }
        pub mod KeyFormat {
          #![allow(non_upper_case_globals)]
          pub type KeyFormat = i32;
          pub const X509: KeyFormat = 0;
          pub const PKCS8: KeyFormat = 1;
          pub const RAW: KeyFormat = 3;
          pub(crate) mod mangled { pub use super::KeyFormat as _7_android_8_hardware_7_keymint_9_KeyFormat; }
        }
        pub mod KeyMintHardwareInfo {
          pub struct KeyMintHardwareInfo {
            pub versionNumber: i32, 
            pub securityLevel: crate::mangled::_7_android_8_hardware_7_keymint_13_SecurityLevel, 
            pub keyMintName: String, 
            pub keyMintAuthorName: String, 
          }
          pub(crate) mod mangled { pub use super::KeyMintHardwareInfo as _7_android_8_hardware_7_keymint_19_KeyMintHardwareInfo; }
          impl Default for KeyMintHardwareInfo {
            fn default() -> Self {
              Self {
                versionNumber: 0,
                securityLevel: Default::default(),
                keyMintName: Default::default(),
                keyMintAuthorName: Default::default(),
              }
            }
          }
          impl binder::parcel::Serialize for KeyMintHardwareInfo {
            fn serialize(&self, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              <Self as binder::parcel::SerializeOption>::serialize_option(Some(self), parcel)
            }
          }
          impl binder::parcel::SerializeArray for KeyMintHardwareInfo {}
          impl binder::parcel::SerializeOption for KeyMintHardwareInfo {
            fn serialize_option(this: Option<&Self>, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              let this = if let Some(this) = this {
                parcel.write(&1i32)?;
                this
              } else {
                return parcel.write(&0i32);
              };
              let start_pos = parcel.get_data_position();
              parcel.write(&0i32)?;
              parcel.write(&this.versionNumber)?;
              parcel.write(&this.securityLevel)?;
              parcel.write(&this.keyMintName)?;
              parcel.write(&this.keyMintAuthorName)?;
              let end_pos = parcel.get_data_position();
              let parcelable_size = (end_pos - start_pos) as i32;
              unsafe { parcel.set_data_position(start_pos)?; }
              parcel.write(&parcelable_size)?;
              unsafe { parcel.set_data_position(end_pos)?; }
              Ok(())
            }
          }
          impl binder::parcel::Deserialize for KeyMintHardwareInfo {
            fn deserialize(parcel: &binder::parcel::Parcel) -> binder::Result<Self> {
              <Self as binder::parcel::DeserializeOption>::deserialize_option(parcel)
                 .transpose()
                 .unwrap_or(Err(binder::StatusCode::UNEXPECTED_NULL))
            }
          }
          impl binder::parcel::DeserializeArray for KeyMintHardwareInfo {}
          impl binder::parcel::DeserializeOption for KeyMintHardwareInfo {
            fn deserialize_option(parcel: &binder::parcel::Parcel) -> binder::Result<Option<Self>> {
              let status: i32 = parcel.read()?;
              if status == 0 { return Ok(None); }
              let start_pos = parcel.get_data_position();
              let parcelable_size: i32 = parcel.read()?;
              if parcelable_size < 0 { return Err(binder::StatusCode::BAD_VALUE); }
              let mut result = Self::default();
              result.versionNumber = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.securityLevel = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.keyMintName = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.keyMintAuthorName = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod KeyOrigin {
          #![allow(non_upper_case_globals)]
          pub type KeyOrigin = i32;
          pub const GENERATED: KeyOrigin = 0;
          pub const DERIVED: KeyOrigin = 1;
          pub const IMPORTED: KeyOrigin = 2;
          pub const SECURELY_IMPORTED: KeyOrigin = 4;
          pub(crate) mod mangled { pub use super::KeyOrigin as _7_android_8_hardware_7_keymint_9_KeyOrigin; }
        }
        pub mod KeyParameter {
          pub struct KeyParameter {
            pub tag: crate::mangled::_7_android_8_hardware_7_keymint_3_Tag, 
            pub boolValue: bool, 
            pub integer: i32, 
            pub longInteger: i64, 
            pub dateTime: i64, 
            pub blob: Vec<u8>, 
          }
          pub(crate) mod mangled { pub use super::KeyParameter as _7_android_8_hardware_7_keymint_12_KeyParameter; }
          impl Default for KeyParameter {
            fn default() -> Self {
              Self {
                tag: Default::default(),
                boolValue: false,
                integer: 0,
                longInteger: 0,
                dateTime: 0,
                blob: Default::default(),
              }
            }
          }
          impl binder::parcel::Serialize for KeyParameter {
            fn serialize(&self, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              <Self as binder::parcel::SerializeOption>::serialize_option(Some(self), parcel)
            }
          }
          impl binder::parcel::SerializeArray for KeyParameter {}
          impl binder::parcel::SerializeOption for KeyParameter {
            fn serialize_option(this: Option<&Self>, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              let this = if let Some(this) = this {
                parcel.write(&1i32)?;
                this
              } else {
                return parcel.write(&0i32);
              };
              let start_pos = parcel.get_data_position();
              parcel.write(&0i32)?;
              parcel.write(&this.tag)?;
              parcel.write(&this.boolValue)?;
              parcel.write(&this.integer)?;
              parcel.write(&this.longInteger)?;
              parcel.write(&this.dateTime)?;
              parcel.write(&this.blob)?;
              let end_pos = parcel.get_data_position();
              let parcelable_size = (end_pos - start_pos) as i32;
              unsafe { parcel.set_data_position(start_pos)?; }
              parcel.write(&parcelable_size)?;
              unsafe { parcel.set_data_position(end_pos)?; }
              Ok(())
            }
          }
          impl binder::parcel::Deserialize for KeyParameter {
            fn deserialize(parcel: &binder::parcel::Parcel) -> binder::Result<Self> {
              <Self as binder::parcel::DeserializeOption>::deserialize_option(parcel)
                 .transpose()
                 .unwrap_or(Err(binder::StatusCode::UNEXPECTED_NULL))
            }
          }
          impl binder::parcel::DeserializeArray for KeyParameter {}
          impl binder::parcel::DeserializeOption for KeyParameter {
            fn deserialize_option(parcel: &binder::parcel::Parcel) -> binder::Result<Option<Self>> {
              let status: i32 = parcel.read()?;
              if status == 0 { return Ok(None); }
              let start_pos = parcel.get_data_position();
              let parcelable_size: i32 = parcel.read()?;
              if parcelable_size < 0 { return Err(binder::StatusCode::BAD_VALUE); }
              let mut result = Self::default();
              result.tag = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.boolValue = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.integer = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.longInteger = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.dateTime = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.blob = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod KeyPurpose {
          #![allow(non_upper_case_globals)]
          pub type KeyPurpose = i32;
          pub const ENCRYPT: KeyPurpose = 0;
          pub const DECRYPT: KeyPurpose = 1;
          pub const SIGN: KeyPurpose = 2;
          pub const VERIFY: KeyPurpose = 3;
          pub const WRAP_KEY: KeyPurpose = 5;
          pub(crate) mod mangled { pub use super::KeyPurpose as _7_android_8_hardware_7_keymint_10_KeyPurpose; }
        }
        pub mod PaddingMode {
          #![allow(non_upper_case_globals)]
          pub type PaddingMode = i32;
          pub const NONE: PaddingMode = 1;
          pub const RSA_OAEP: PaddingMode = 2;
          pub const RSA_PSS: PaddingMode = 3;
          pub const RSA_PKCS1_1_5_ENCRYPT: PaddingMode = 4;
          pub const RSA_PKCS1_1_5_SIGN: PaddingMode = 5;
          pub const PKCS7: PaddingMode = 64;
          pub(crate) mod mangled { pub use super::PaddingMode as _7_android_8_hardware_7_keymint_11_PaddingMode; }
        }
        pub mod SecurityLevel {
          #![allow(non_upper_case_globals)]
          pub type SecurityLevel = i32;
          pub const SOFTWARE: SecurityLevel = 0;
          pub const TRUSTED_ENVIRONMENT: SecurityLevel = 1;
          pub const STRONGBOX: SecurityLevel = 2;
          pub(crate) mod mangled { pub use super::SecurityLevel as _7_android_8_hardware_7_keymint_13_SecurityLevel; }
        }
        pub mod Tag {
          #![allow(non_upper_case_globals)]
          pub type Tag = i32;
          pub const INVALID: Tag = 0;
          pub const PURPOSE: Tag = 536870913;
          pub const ALGORITHM: Tag = 268435458;
          pub const KEY_SIZE: Tag = 805306371;
          pub const BLOCK_MODE: Tag = 536870916;
          pub const DIGEST: Tag = 536870917;
          pub const PADDING: Tag = 536870918;
          pub const CALLER_NONCE: Tag = 1879048199;
          pub const MIN_MAC_LENGTH: Tag = 805306376;
          pub const EC_CURVE: Tag = 268435466;
          pub const RSA_PUBLIC_EXPONENT: Tag = 1342177480;
          pub const INCLUDE_UNIQUE_ID: Tag = 1879048394;
          pub const BLOB_USAGE_REQUIREMENTS: Tag = 268435757;
          pub const BOOTLOADER_ONLY: Tag = 1879048494;
          pub const ROLLBACK_RESISTANCE: Tag = 1879048495;
          pub const HARDWARE_TYPE: Tag = 268435760;
          pub const EARLY_BOOT_ONLY: Tag = 1879048497;
          pub const ACTIVE_DATETIME: Tag = 1610613136;
          pub const ORIGINATION_EXPIRE_DATETIME: Tag = 1610613137;
          pub const USAGE_EXPIRE_DATETIME: Tag = 1610613138;
          pub const MIN_SECONDS_BETWEEN_OPS: Tag = 805306771;
          pub const MAX_USES_PER_BOOT: Tag = 805306772;
          pub const USER_ID: Tag = 805306869;
          pub const USER_SECURE_ID: Tag = 1073742326;
          pub const NO_AUTH_REQUIRED: Tag = 1879048695;
          pub const USER_AUTH_TYPE: Tag = 268435960;
          pub const AUTH_TIMEOUT: Tag = 805306873;
          pub const ALLOW_WHILE_ON_BODY: Tag = 1879048698;
          pub const TRUSTED_USER_PRESENCE_REQUIRED: Tag = 1879048699;
          pub const TRUSTED_CONFIRMATION_REQUIRED: Tag = 1879048700;
          pub const UNLOCKED_DEVICE_REQUIRED: Tag = 1879048701;
          pub const APPLICATION_ID: Tag = -1879047591;
          pub const APPLICATION_DATA: Tag = -1879047492;
          pub const CREATION_DATETIME: Tag = 1610613437;
          pub const ORIGIN: Tag = 268436158;
          pub const ROOT_OF_TRUST: Tag = -1879047488;
          pub const OS_VERSION: Tag = 805307073;
          pub const OS_PATCHLEVEL: Tag = 805307074;
          pub const UNIQUE_ID: Tag = -1879047485;
          pub const ATTESTATION_CHALLENGE: Tag = -1879047484;
          pub const ATTESTATION_APPLICATION_ID: Tag = -1879047483;
          pub const ATTESTATION_ID_BRAND: Tag = -1879047482;
          pub const ATTESTATION_ID_DEVICE: Tag = -1879047481;
          pub const ATTESTATION_ID_PRODUCT: Tag = -1879047480;
          pub const ATTESTATION_ID_SERIAL: Tag = -1879047479;
          pub const ATTESTATION_ID_IMEI: Tag = -1879047478;
          pub const ATTESTATION_ID_MEID: Tag = -1879047477;
          pub const ATTESTATION_ID_MANUFACTURER: Tag = -1879047476;
          pub const ATTESTATION_ID_MODEL: Tag = -1879047475;
          pub const VENDOR_PATCHLEVEL: Tag = 805307086;
          pub const BOOT_PATCHLEVEL: Tag = 805307087;
          pub const DEVICE_UNIQUE_ATTESTATION: Tag = 1879048912;
          pub const IDENTITY_CREDENTIAL_KEY: Tag = 1879048913;
          pub const STORAGE_KEY: Tag = 1879048914;
          pub const ASSOCIATED_DATA: Tag = -1879047192;
          pub const NONCE: Tag = -1879047191;
          pub const MAC_LENGTH: Tag = 805307371;
          pub const RESET_SINCE_ID_ROTATION: Tag = 1879049196;
          pub const CONFIRMATION_TOKEN: Tag = -1879047187;
          pub(crate) mod mangled { pub use super::Tag as _7_android_8_hardware_7_keymint_3_Tag; }
        }
        pub mod TagType {
          #![allow(non_upper_case_globals)]
          pub type TagType = i32;
          pub const INVALID: TagType = 0;
          pub const ENUM: TagType = 268435456;
          pub const ENUM_REP: TagType = 536870912;
          pub const UINT: TagType = 805306368;
          pub const UINT_REP: TagType = 1073741824;
          pub const ULONG: TagType = 1342177280;
          pub const DATE: TagType = 1610612736;
          pub const BOOL: TagType = 1879048192;
          pub const BIGNUM: TagType = -2147483648;
          pub const BYTES: TagType = -1879048192;
          pub const ULONG_REP: TagType = -1610612736;
          pub(crate) mod mangled { pub use super::TagType as _7_android_8_hardware_7_keymint_7_TagType; }
        }
        pub mod Timestamp {
          pub struct Timestamp {
            pub milliSeconds: i64, 
          }
          pub(crate) mod mangled { pub use super::Timestamp as _7_android_8_hardware_7_keymint_9_Timestamp; }
          impl Default for Timestamp {
            fn default() -> Self {
              Self {
                milliSeconds: 0,
              }
            }
          }
          impl binder::parcel::Serialize for Timestamp {
            fn serialize(&self, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              <Self as binder::parcel::SerializeOption>::serialize_option(Some(self), parcel)
            }
          }
          impl binder::parcel::SerializeArray for Timestamp {}
          impl binder::parcel::SerializeOption for Timestamp {
            fn serialize_option(this: Option<&Self>, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              let this = if let Some(this) = this {
                parcel.write(&1i32)?;
                this
              } else {
                return parcel.write(&0i32);
              };
              let start_pos = parcel.get_data_position();
              parcel.write(&0i32)?;
              parcel.write(&this.milliSeconds)?;
              let end_pos = parcel.get_data_position();
              let parcelable_size = (end_pos - start_pos) as i32;
              unsafe { parcel.set_data_position(start_pos)?; }
              parcel.write(&parcelable_size)?;
              unsafe { parcel.set_data_position(end_pos)?; }
              Ok(())
            }
          }
          impl binder::parcel::Deserialize for Timestamp {
            fn deserialize(parcel: &binder::parcel::Parcel) -> binder::Result<Self> {
              <Self as binder::parcel::DeserializeOption>::deserialize_option(parcel)
                 .transpose()
                 .unwrap_or(Err(binder::StatusCode::UNEXPECTED_NULL))
            }
          }
          impl binder::parcel::DeserializeArray for Timestamp {}
          impl binder::parcel::DeserializeOption for Timestamp {
            fn deserialize_option(parcel: &binder::parcel::Parcel) -> binder::Result<Option<Self>> {
              let status: i32 = parcel.read()?;
              if status == 0 { return Ok(None); }
              let start_pos = parcel.get_data_position();
              let parcelable_size: i32 = parcel.read()?;
              if parcelable_size < 0 { return Err(binder::StatusCode::BAD_VALUE); }
              let mut result = Self::default();
              result.milliSeconds = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod VerificationToken {
          pub struct VerificationToken {
            pub challenge: i64, 
            pub timestamp: crate::mangled::_7_android_8_hardware_7_keymint_9_Timestamp, 
            pub securityLevel: crate::mangled::_7_android_8_hardware_7_keymint_13_SecurityLevel, 
            pub mac: Vec<u8>, 
          }
          pub(crate) mod mangled { pub use super::VerificationToken as _7_android_8_hardware_7_keymint_17_VerificationToken; }
          impl Default for VerificationToken {
            fn default() -> Self {
              Self {
                challenge: 0,
                timestamp: Default::default(),
                securityLevel: Default::default(),
                mac: Default::default(),
              }
            }
          }
          impl binder::parcel::Serialize for VerificationToken {
            fn serialize(&self, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              <Self as binder::parcel::SerializeOption>::serialize_option(Some(self), parcel)
            }
          }
          impl binder::parcel::SerializeArray for VerificationToken {}
          impl binder::parcel::SerializeOption for VerificationToken {
            fn serialize_option(this: Option<&Self>, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              let this = if let Some(this) = this {
                parcel.write(&1i32)?;
                this
              } else {
                return parcel.write(&0i32);
              };
              let start_pos = parcel.get_data_position();
              parcel.write(&0i32)?;
              parcel.write(&this.challenge)?;
              parcel.write(&this.timestamp)?;
              parcel.write(&this.securityLevel)?;
              parcel.write(&this.mac)?;
              let end_pos = parcel.get_data_position();
              let parcelable_size = (end_pos - start_pos) as i32;
              unsafe { parcel.set_data_position(start_pos)?; }
              parcel.write(&parcelable_size)?;
              unsafe { parcel.set_data_position(end_pos)?; }
              Ok(())
            }
          }
          impl binder::parcel::Deserialize for VerificationToken {
            fn deserialize(parcel: &binder::parcel::Parcel) -> binder::Result<Self> {
              <Self as binder::parcel::DeserializeOption>::deserialize_option(parcel)
                 .transpose()
                 .unwrap_or(Err(binder::StatusCode::UNEXPECTED_NULL))
            }
          }
          impl binder::parcel::DeserializeArray for VerificationToken {}
          impl binder::parcel::DeserializeOption for VerificationToken {
            fn deserialize_option(parcel: &binder::parcel::Parcel) -> binder::Result<Option<Self>> {
              let status: i32 = parcel.read()?;
              if status == 0 { return Ok(None); }
              let start_pos = parcel.get_data_position();
              let parcelable_size: i32 = parcel.read()?;
              if parcelable_size < 0 { return Err(binder::StatusCode::BAD_VALUE); }
              let mut result = Self::default();
              result.challenge = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.timestamp = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.securityLevel = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.mac = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
      }
    }
  }
}
pub mod mangled {
  pub use super::aidl::android::hardware::keymint::Algorithm::mangled::*;
  pub use super::aidl::android::hardware::keymint::BeginResult::mangled::*;
  pub use super::aidl::android::hardware::keymint::BlockMode::mangled::*;
  pub use super::aidl::android::hardware::keymint::Certificate::mangled::*;
  pub use super::aidl::android::hardware::keymint::Constants::mangled::*;
  pub use super::aidl::android::hardware::keymint::Digest::mangled::*;
  pub use super::aidl::android::hardware::keymint::EcCurve::mangled::*;
  pub use super::aidl::android::hardware::keymint::ErrorCode::mangled::*;
  pub use super::aidl::android::hardware::keymint::HardwareAuthToken::mangled::*;
  pub use super::aidl::android::hardware::keymint::HardwareAuthenticatorType::mangled::*;
  pub use super::aidl::android::hardware::keymint::HmacSharingParameters::mangled::*;
  pub use super::aidl::android::hardware::keymint::IKeyMintDevice::mangled::*;
  pub use super::aidl::android::hardware::keymint::IKeyMintOperation::mangled::*;
  pub use super::aidl::android::hardware::keymint::KeyCharacteristics::mangled::*;
  pub use super::aidl::android::hardware::keymint::KeyDerivationFunction::mangled::*;
  pub use super::aidl::android::hardware::keymint::KeyFormat::mangled::*;
  pub use super::aidl::android::hardware::keymint::KeyMintHardwareInfo::mangled::*;
  pub use super::aidl::android::hardware::keymint::KeyOrigin::mangled::*;
  pub use super::aidl::android::hardware::keymint::KeyParameter::mangled::*;
  pub use super::aidl::android::hardware::keymint::KeyPurpose::mangled::*;
  pub use super::aidl::android::hardware::keymint::PaddingMode::mangled::*;
  pub use super::aidl::android::hardware::keymint::SecurityLevel::mangled::*;
  pub use super::aidl::android::hardware::keymint::Tag::mangled::*;
  pub use super::aidl::android::hardware::keymint::TagType::mangled::*;
  pub use super::aidl::android::hardware::keymint::Timestamp::mangled::*;
  pub use super::aidl::android::hardware::keymint::VerificationToken::mangled::*;
}
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
          use binder::declare_binder_enum;
          declare_binder_enum! { Algorithm : i32 {
            RSA = 1,
            EC = 3,
            AES = 32,
            TRIPLE_DES = 33,
            HMAC = 128,
          } }
          pub(crate) mod mangled { pub use super::Algorithm as _7_android_8_hardware_7_keymint_9_Algorithm; }
        }
        pub mod BeginResult {
          #[derive(Debug)]
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
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.params = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.operation = Some(parcel.read()?);
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod BlockMode {
          #![allow(non_upper_case_globals)]
          use binder::declare_binder_enum;
          declare_binder_enum! { BlockMode : i32 {
            ECB = 1,
            CBC = 2,
            CTR = 3,
            GCM = 32,
          } }
          pub(crate) mod mangled { pub use super::BlockMode as _7_android_8_hardware_7_keymint_9_BlockMode; }
        }
        pub mod Certificate {
          #[derive(Debug)]
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
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod Constants {
          #![allow(non_upper_case_globals)]
          use binder::declare_binder_enum;
          declare_binder_enum! { Constants : i32 {
            AUTH_TOKEN_MAC_LENGTH = 32,
          } }
          pub(crate) mod mangled { pub use super::Constants as _7_android_8_hardware_7_keymint_9_Constants; }
        }
        pub mod Digest {
          #![allow(non_upper_case_globals)]
          use binder::declare_binder_enum;
          declare_binder_enum! { Digest : i32 {
            NONE = 0,
            MD5 = 1,
            SHA1 = 2,
            SHA_2_224 = 3,
            SHA_2_256 = 4,
            SHA_2_384 = 5,
            SHA_2_512 = 6,
          } }
          pub(crate) mod mangled { pub use super::Digest as _7_android_8_hardware_7_keymint_6_Digest; }
        }
        pub mod EcCurve {
          #![allow(non_upper_case_globals)]
          use binder::declare_binder_enum;
          declare_binder_enum! { EcCurve : i32 {
            P_224 = 0,
            P_256 = 1,
            P_384 = 2,
            P_521 = 3,
          } }
          pub(crate) mod mangled { pub use super::EcCurve as _7_android_8_hardware_7_keymint_7_EcCurve; }
        }
        pub mod ErrorCode {
          #![allow(non_upper_case_globals)]
          use binder::declare_binder_enum;
          declare_binder_enum! { ErrorCode : i32 {
            OK = 0,
            ROOT_OF_TRUST_ALREADY_SET = -1,
            UNSUPPORTED_PURPOSE = -2,
            INCOMPATIBLE_PURPOSE = -3,
            UNSUPPORTED_ALGORITHM = -4,
            INCOMPATIBLE_ALGORITHM = -5,
            UNSUPPORTED_KEY_SIZE = -6,
            UNSUPPORTED_BLOCK_MODE = -7,
            INCOMPATIBLE_BLOCK_MODE = -8,
            UNSUPPORTED_MAC_LENGTH = -9,
            UNSUPPORTED_PADDING_MODE = -10,
            INCOMPATIBLE_PADDING_MODE = -11,
            UNSUPPORTED_DIGEST = -12,
            INCOMPATIBLE_DIGEST = -13,
            INVALID_EXPIRATION_TIME = -14,
            INVALID_USER_ID = -15,
            INVALID_AUTHORIZATION_TIMEOUT = -16,
            UNSUPPORTED_KEY_FORMAT = -17,
            INCOMPATIBLE_KEY_FORMAT = -18,
            UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM = -19,
            UNSUPPORTED_KEY_VERIFICATION_ALGORITHM = -20,
            INVALID_INPUT_LENGTH = -21,
            KEY_EXPORT_OPTIONS_INVALID = -22,
            DELEGATION_NOT_ALLOWED = -23,
            KEY_NOT_YET_VALID = -24,
            KEY_EXPIRED = -25,
            KEY_USER_NOT_AUTHENTICATED = -26,
            OUTPUT_PARAMETER_NULL = -27,
            INVALID_OPERATION_HANDLE = -28,
            INSUFFICIENT_BUFFER_SPACE = -29,
            VERIFICATION_FAILED = -30,
            TOO_MANY_OPERATIONS = -31,
            UNEXPECTED_NULL_POINTER = -32,
            INVALID_KEY_BLOB = -33,
            IMPORTED_KEY_NOT_ENCRYPTED = -34,
            IMPORTED_KEY_DECRYPTION_FAILED = -35,
            IMPORTED_KEY_NOT_SIGNED = -36,
            IMPORTED_KEY_VERIFICATION_FAILED = -37,
            INVALID_ARGUMENT = -38,
            UNSUPPORTED_TAG = -39,
            INVALID_TAG = -40,
            MEMORY_ALLOCATION_FAILED = -41,
            IMPORT_PARAMETER_MISMATCH = -44,
            SECURE_HW_ACCESS_DENIED = -45,
            OPERATION_CANCELLED = -46,
            CONCURRENT_ACCESS_CONFLICT = -47,
            SECURE_HW_BUSY = -48,
            SECURE_HW_COMMUNICATION_FAILED = -49,
            UNSUPPORTED_EC_FIELD = -50,
            MISSING_NONCE = -51,
            INVALID_NONCE = -52,
            MISSING_MAC_LENGTH = -53,
            KEY_RATE_LIMIT_EXCEEDED = -54,
            CALLER_NONCE_PROHIBITED = -55,
            KEY_MAX_OPS_EXCEEDED = -56,
            INVALID_MAC_LENGTH = -57,
            MISSING_MIN_MAC_LENGTH = -58,
            UNSUPPORTED_MIN_MAC_LENGTH = -59,
            UNSUPPORTED_KDF = -60,
            UNSUPPORTED_EC_CURVE = -61,
            KEY_REQUIRES_UPGRADE = -62,
            ATTESTATION_CHALLENGE_MISSING = -63,
            KEYMINT_NOT_CONFIGURED = -64,
            ATTESTATION_APPLICATION_ID_MISSING = -65,
            CANNOT_ATTEST_IDS = -66,
            ROLLBACK_RESISTANCE_UNAVAILABLE = -67,
            HARDWARE_TYPE_UNAVAILABLE = -68,
            PROOF_OF_PRESENCE_REQUIRED = -69,
            CONCURRENT_PROOF_OF_PRESENCE_REQUESTED = -70,
            NO_USER_CONFIRMATION = -71,
            DEVICE_LOCKED = -72,
            EARLY_BOOT_ENDED = -73,
            ATTESTATION_KEYS_NOT_PROVISIONED = -74,
            ATTESTATION_IDS_NOT_PROVISIONED = -75,
            INVALID_OPERATION = -76,
            STORAGE_KEY_UNSUPPORTED = -77,
            UNIMPLEMENTED = -100,
            VERSION_MISMATCH = -101,
            UNKNOWN_ERROR = -1000,
          } }
          pub(crate) mod mangled { pub use super::ErrorCode as _7_android_8_hardware_7_keymint_9_ErrorCode; }
        }
        pub mod HardwareAuthToken {
          #[derive(Debug)]
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
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.userId = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.authenticatorId = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.authenticatorType = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.timestamp = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.mac = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod HardwareAuthenticatorType {
          #![allow(non_upper_case_globals)]
          use binder::declare_binder_enum;
          declare_binder_enum! { HardwareAuthenticatorType : i32 {
            NONE = 0,
            PASSWORD = 1,
            FINGERPRINT = 2,
            ANY = -1,
          } }
          pub(crate) mod mangled { pub use super::HardwareAuthenticatorType as _7_android_8_hardware_7_keymint_25_HardwareAuthenticatorType; }
        }
        pub mod HmacSharingParameters {
          #[derive(Debug)]
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
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.nonce = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
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
          pub trait IKeyMintDevice: binder::Interface + Send {
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
            fn getDefaultImpl() -> IKeyMintDeviceDefault where Self: Sized {
              DEFAULT_IMPL.lock().unwrap().clone()
            }
            fn setDefaultImpl(d: IKeyMintDeviceDefault) -> IKeyMintDeviceDefault where Self: Sized {
              std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
            }
          }
          pub mod transactions {
            #[allow(unused_imports)] use binder::IBinder;
            pub const getHardwareInfo: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 0;
            pub const verifyAuthorization: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 1;
            pub const addRngEntropy: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 2;
            pub const generateKey: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 3;
            pub const importKey: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 4;
            pub const importWrappedKey: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 5;
            pub const upgradeKey: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 6;
            pub const deleteKey: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 7;
            pub const deleteAllKeys: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 8;
            pub const destroyAttestationIds: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 9;
            pub const begin: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 10;
          }
          pub type IKeyMintDeviceDefault = Option<std::sync::Arc<dyn IKeyMintDevice + Sync>>;
          use lazy_static::lazy_static;
          lazy_static! {
            static ref DEFAULT_IMPL: std::sync::Mutex<IKeyMintDeviceDefault> = std::sync::Mutex::new(None);
          }
          pub(crate) mod mangled { pub use super::IKeyMintDevice as _7_android_8_hardware_7_keymint_14_IKeyMintDevice; }
          impl IKeyMintDevice for BpKeyMintDevice {
            fn getHardwareInfo(&self) -> binder::public_api::Result<crate::mangled::_7_android_8_hardware_7_keymint_19_KeyMintHardwareInfo> {
              let _aidl_reply = self.binder.transact(transactions::getHardwareInfo, 0, |_aidl_data| {
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
              let _aidl_reply = self.binder.transact(transactions::verifyAuthorization, 0, |_aidl_data| {
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
              let _aidl_reply = self.binder.transact(transactions::addRngEntropy, 0, |_aidl_data| {
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
              let _aidl_reply = self.binder.transact(transactions::generateKey, 0, |_aidl_data| {
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
              let _aidl_reply = self.binder.transact(transactions::importKey, 0, |_aidl_data| {
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
              let _aidl_reply = self.binder.transact(transactions::importWrappedKey, 0, |_aidl_data| {
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
              let _aidl_reply = self.binder.transact(transactions::upgradeKey, 0, |_aidl_data| {
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
              let _aidl_reply = self.binder.transact(transactions::deleteKey, 0, |_aidl_data| {
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
              let _aidl_reply = self.binder.transact(transactions::deleteAllKeys, 0, |_aidl_data| {
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
              let _aidl_reply = self.binder.transact(transactions::destroyAttestationIds, 0, |_aidl_data| {
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
              let _aidl_reply = self.binder.transact(transactions::begin, 0, |_aidl_data| {
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
              transactions::getHardwareInfo => {
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
              transactions::verifyAuthorization => {
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
              transactions::addRngEntropy => {
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
              transactions::generateKey => {
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
              transactions::importKey => {
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
              transactions::importWrappedKey => {
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
              transactions::upgradeKey => {
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
              transactions::deleteKey => {
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
              transactions::deleteAllKeys => {
                let _aidl_return = _aidl_service.deleteAllKeys();
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              transactions::destroyAttestationIds => {
                let _aidl_return = _aidl_service.destroyAttestationIds();
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              transactions::begin => {
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
          pub trait IKeyMintOperation: binder::Interface + Send {
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
            fn getDefaultImpl() -> IKeyMintOperationDefault where Self: Sized {
              DEFAULT_IMPL.lock().unwrap().clone()
            }
            fn setDefaultImpl(d: IKeyMintOperationDefault) -> IKeyMintOperationDefault where Self: Sized {
              std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
            }
          }
          pub mod transactions {
            #[allow(unused_imports)] use binder::IBinder;
            pub const update: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 0;
            pub const finish: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 1;
            pub const abort: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 2;
          }
          pub type IKeyMintOperationDefault = Option<std::sync::Arc<dyn IKeyMintOperation + Sync>>;
          use lazy_static::lazy_static;
          lazy_static! {
            static ref DEFAULT_IMPL: std::sync::Mutex<IKeyMintOperationDefault> = std::sync::Mutex::new(None);
          }
          pub(crate) mod mangled { pub use super::IKeyMintOperation as _7_android_8_hardware_7_keymint_17_IKeyMintOperation; }
          impl IKeyMintOperation for BpKeyMintOperation {
            fn update(&self, _arg_inParams: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_input: &[u8], _arg_inVerificationToken: &crate::mangled::_7_android_8_hardware_7_keymint_17_VerificationToken, _arg_outParams: &mut Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter>, _arg_output: &mut Vec<u8>) -> binder::public_api::Result<i32> {
              let _aidl_reply = self.binder.transact(transactions::update, 0, |_aidl_data| {
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
              let _aidl_reply = self.binder.transact(transactions::finish, 0, |_aidl_data| {
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
              let _aidl_reply = self.binder.transact(transactions::abort, 0, |_aidl_data| {
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
              transactions::update => {
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
              transactions::finish => {
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
              transactions::abort => {
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
          #[derive(Debug)]
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
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.hardwareEnforced = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod KeyDerivationFunction {
          #![allow(non_upper_case_globals)]
          use binder::declare_binder_enum;
          declare_binder_enum! { KeyDerivationFunction : i32 {
            NONE = 0,
            RFC5869_SHA256 = 1,
            ISO18033_2_KDF1_SHA1 = 2,
            ISO18033_2_KDF1_SHA256 = 3,
            ISO18033_2_KDF2_SHA1 = 4,
            ISO18033_2_KDF2_SHA256 = 5,
          } }
          pub(crate) mod mangled { pub use super::KeyDerivationFunction as _7_android_8_hardware_7_keymint_21_KeyDerivationFunction; }
        }
        pub mod KeyFormat {
          #![allow(non_upper_case_globals)]
          use binder::declare_binder_enum;
          declare_binder_enum! { KeyFormat : i32 {
            X509 = 0,
            PKCS8 = 1,
            RAW = 3,
          } }
          pub(crate) mod mangled { pub use super::KeyFormat as _7_android_8_hardware_7_keymint_9_KeyFormat; }
        }
        pub mod KeyMintHardwareInfo {
          #[derive(Debug)]
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
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.securityLevel = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.keyMintName = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.keyMintAuthorName = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod KeyOrigin {
          #![allow(non_upper_case_globals)]
          use binder::declare_binder_enum;
          declare_binder_enum! { KeyOrigin : i32 {
            GENERATED = 0,
            DERIVED = 1,
            IMPORTED = 2,
            RESERVED = 3,
            SECURELY_IMPORTED = 4,
          } }
          pub(crate) mod mangled { pub use super::KeyOrigin as _7_android_8_hardware_7_keymint_9_KeyOrigin; }
        }
        pub mod KeyParameter {
          #[derive(Debug)]
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
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.boolValue = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.integer = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.longInteger = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.dateTime = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.blob = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod KeyPurpose {
          #![allow(non_upper_case_globals)]
          use binder::declare_binder_enum;
          declare_binder_enum! { KeyPurpose : i32 {
            ENCRYPT = 0,
            DECRYPT = 1,
            SIGN = 2,
            VERIFY = 3,
            WRAP_KEY = 5,
          } }
          pub(crate) mod mangled { pub use super::KeyPurpose as _7_android_8_hardware_7_keymint_10_KeyPurpose; }
        }
        pub mod PaddingMode {
          #![allow(non_upper_case_globals)]
          use binder::declare_binder_enum;
          declare_binder_enum! { PaddingMode : i32 {
            NONE = 1,
            RSA_OAEP = 2,
            RSA_PSS = 3,
            RSA_PKCS1_1_5_ENCRYPT = 4,
            RSA_PKCS1_1_5_SIGN = 5,
            PKCS7 = 64,
          } }
          pub(crate) mod mangled { pub use super::PaddingMode as _7_android_8_hardware_7_keymint_11_PaddingMode; }
        }
        pub mod SecurityLevel {
          #![allow(non_upper_case_globals)]
          use binder::declare_binder_enum;
          declare_binder_enum! { SecurityLevel : i32 {
            SOFTWARE = 0,
            TRUSTED_ENVIRONMENT = 1,
            STRONGBOX = 2,
          } }
          pub(crate) mod mangled { pub use super::SecurityLevel as _7_android_8_hardware_7_keymint_13_SecurityLevel; }
        }
        pub mod Tag {
          #![allow(non_upper_case_globals)]
          use binder::declare_binder_enum;
          declare_binder_enum! { Tag : i32 {
            INVALID = 0,
            PURPOSE = 536870913,
            ALGORITHM = 268435458,
            KEY_SIZE = 805306371,
            BLOCK_MODE = 536870916,
            DIGEST = 536870917,
            PADDING = 536870918,
            CALLER_NONCE = 1879048199,
            MIN_MAC_LENGTH = 805306376,
            EC_CURVE = 268435466,
            RSA_PUBLIC_EXPONENT = 1342177480,
            INCLUDE_UNIQUE_ID = 1879048394,
            BLOB_USAGE_REQUIREMENTS = 268435757,
            BOOTLOADER_ONLY = 1879048494,
            ROLLBACK_RESISTANCE = 1879048495,
            HARDWARE_TYPE = 268435760,
            EARLY_BOOT_ONLY = 1879048497,
            ACTIVE_DATETIME = 1610613136,
            ORIGINATION_EXPIRE_DATETIME = 1610613137,
            USAGE_EXPIRE_DATETIME = 1610613138,
            MIN_SECONDS_BETWEEN_OPS = 805306771,
            MAX_USES_PER_BOOT = 805306772,
            USER_ID = 805306869,
            USER_SECURE_ID = 1073742326,
            NO_AUTH_REQUIRED = 1879048695,
            USER_AUTH_TYPE = 268435960,
            AUTH_TIMEOUT = 805306873,
            ALLOW_WHILE_ON_BODY = 1879048698,
            TRUSTED_USER_PRESENCE_REQUIRED = 1879048699,
            TRUSTED_CONFIRMATION_REQUIRED = 1879048700,
            UNLOCKED_DEVICE_REQUIRED = 1879048701,
            APPLICATION_ID = -1879047591,
            APPLICATION_DATA = -1879047492,
            CREATION_DATETIME = 1610613437,
            ORIGIN = 268436158,
            ROOT_OF_TRUST = -1879047488,
            OS_VERSION = 805307073,
            OS_PATCHLEVEL = 805307074,
            UNIQUE_ID = -1879047485,
            ATTESTATION_CHALLENGE = -1879047484,
            ATTESTATION_APPLICATION_ID = -1879047483,
            ATTESTATION_ID_BRAND = -1879047482,
            ATTESTATION_ID_DEVICE = -1879047481,
            ATTESTATION_ID_PRODUCT = -1879047480,
            ATTESTATION_ID_SERIAL = -1879047479,
            ATTESTATION_ID_IMEI = -1879047478,
            ATTESTATION_ID_MEID = -1879047477,
            ATTESTATION_ID_MANUFACTURER = -1879047476,
            ATTESTATION_ID_MODEL = -1879047475,
            VENDOR_PATCHLEVEL = 805307086,
            BOOT_PATCHLEVEL = 805307087,
            DEVICE_UNIQUE_ATTESTATION = 1879048912,
            IDENTITY_CREDENTIAL_KEY = 1879048913,
            STORAGE_KEY = 1879048914,
            ASSOCIATED_DATA = -1879047192,
            NONCE = -1879047191,
            MAC_LENGTH = 805307371,
            RESET_SINCE_ID_ROTATION = 1879049196,
            CONFIRMATION_TOKEN = -1879047187,
          } }
          pub(crate) mod mangled { pub use super::Tag as _7_android_8_hardware_7_keymint_3_Tag; }
        }
        pub mod TagType {
          #![allow(non_upper_case_globals)]
          use binder::declare_binder_enum;
          declare_binder_enum! { TagType : i32 {
            INVALID = 0,
            ENUM = 268435456,
            ENUM_REP = 536870912,
            UINT = 805306368,
            UINT_REP = 1073741824,
            ULONG = 1342177280,
            DATE = 1610612736,
            BOOL = 1879048192,
            BIGNUM = -2147483648,
            BYTES = -1879048192,
            ULONG_REP = -1610612736,
          } }
          pub(crate) mod mangled { pub use super::TagType as _7_android_8_hardware_7_keymint_7_TagType; }
        }
        pub mod Timestamp {
          #[derive(Debug)]
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
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod VerificationToken {
          #[derive(Debug)]
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
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.timestamp = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.securityLevel = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
                return Ok(Some(result));
              }
              result.mac = parcel.read()?;
              if (parcel.get_data_position() - start_pos) == parcelable_size {
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

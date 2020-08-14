#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(clippy::identity_op)]
#![allow(clippy::excessive_precision)]
#![allow(clippy::too_many_arguments)]
pub use binder::public_api as binder;
pub mod aidl {
  pub mod android {
    pub mod security {
      pub mod keystore2 {
        pub mod AuthenticatorSpec {
          pub struct AuthenticatorSpec {
            pub authenticatorType: crate::mangled::_7_android_8_hardware_7_keymint_25_HardwareAuthenticatorType, 
            pub authenticatorId: i64, 
          }
          pub(crate) mod mangled { pub use super::AuthenticatorSpec as _7_android_8_security_9_keystore2_17_AuthenticatorSpec; }
          impl Default for AuthenticatorSpec {
            fn default() -> Self {
              Self {
                authenticatorType: Default::default(),
                authenticatorId: 0,
              }
            }
          }
          impl binder::parcel::Serialize for AuthenticatorSpec {
            fn serialize(&self, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              <Self as binder::parcel::SerializeOption>::serialize_option(Some(self), parcel)
            }
          }
          impl binder::parcel::SerializeArray for AuthenticatorSpec {}
          impl binder::parcel::SerializeOption for AuthenticatorSpec {
            fn serialize_option(this: Option<&Self>, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              let this = if let Some(this) = this {
                parcel.write(&1i32)?;
                this
              } else {
                return parcel.write(&0i32);
              };
              let start_pos = parcel.get_data_position();
              parcel.write(&0i32)?;
              parcel.write(&this.authenticatorType)?;
              parcel.write(&this.authenticatorId)?;
              let end_pos = parcel.get_data_position();
              let parcelable_size = (end_pos - start_pos) as i32;
              unsafe { parcel.set_data_position(start_pos)?; }
              parcel.write(&parcelable_size)?;
              unsafe { parcel.set_data_position(end_pos)?; }
              Ok(())
            }
          }
          impl binder::parcel::Deserialize for AuthenticatorSpec {
            fn deserialize(parcel: &binder::parcel::Parcel) -> binder::Result<Self> {
              <Self as binder::parcel::DeserializeOption>::deserialize_option(parcel)
                 .transpose()
                 .unwrap_or(Err(binder::StatusCode::UNEXPECTED_NULL))
            }
          }
          impl binder::parcel::DeserializeArray for AuthenticatorSpec {}
          impl binder::parcel::DeserializeOption for AuthenticatorSpec {
            fn deserialize_option(parcel: &binder::parcel::Parcel) -> binder::Result<Option<Self>> {
              let status: i32 = parcel.read()?;
              if status == 0 { return Ok(None); }
              let start_pos = parcel.get_data_position();
              let parcelable_size: i32 = parcel.read()?;
              if parcelable_size < 0 { return Err(binder::StatusCode::BAD_VALUE); }
              let mut result = Self::default();
              result.authenticatorType = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.authenticatorId = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod Certificate {
          pub struct Certificate {
            pub data: Vec<u8>, 
          }
          pub(crate) mod mangled { pub use super::Certificate as _7_android_8_security_9_keystore2_11_Certificate; }
          impl Default for Certificate {
            fn default() -> Self {
              Self {
                data: Default::default(),
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
              parcel.write(&this.data)?;
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
              result.data = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod CertificateChain {
          pub struct CertificateChain {
            pub certificates: Vec<crate::mangled::_7_android_8_security_9_keystore2_11_Certificate>, 
          }
          pub(crate) mod mangled { pub use super::CertificateChain as _7_android_8_security_9_keystore2_16_CertificateChain; }
          impl Default for CertificateChain {
            fn default() -> Self {
              Self {
                certificates: Default::default(),
              }
            }
          }
          impl binder::parcel::Serialize for CertificateChain {
            fn serialize(&self, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              <Self as binder::parcel::SerializeOption>::serialize_option(Some(self), parcel)
            }
          }
          impl binder::parcel::SerializeArray for CertificateChain {}
          impl binder::parcel::SerializeOption for CertificateChain {
            fn serialize_option(this: Option<&Self>, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              let this = if let Some(this) = this {
                parcel.write(&1i32)?;
                this
              } else {
                return parcel.write(&0i32);
              };
              let start_pos = parcel.get_data_position();
              parcel.write(&0i32)?;
              parcel.write(&this.certificates)?;
              let end_pos = parcel.get_data_position();
              let parcelable_size = (end_pos - start_pos) as i32;
              unsafe { parcel.set_data_position(start_pos)?; }
              parcel.write(&parcelable_size)?;
              unsafe { parcel.set_data_position(end_pos)?; }
              Ok(())
            }
          }
          impl binder::parcel::Deserialize for CertificateChain {
            fn deserialize(parcel: &binder::parcel::Parcel) -> binder::Result<Self> {
              <Self as binder::parcel::DeserializeOption>::deserialize_option(parcel)
                 .transpose()
                 .unwrap_or(Err(binder::StatusCode::UNEXPECTED_NULL))
            }
          }
          impl binder::parcel::DeserializeArray for CertificateChain {}
          impl binder::parcel::DeserializeOption for CertificateChain {
            fn deserialize_option(parcel: &binder::parcel::Parcel) -> binder::Result<Option<Self>> {
              let status: i32 = parcel.read()?;
              if status == 0 { return Ok(None); }
              let start_pos = parcel.get_data_position();
              let parcelable_size: i32 = parcel.read()?;
              if parcelable_size < 0 { return Err(binder::StatusCode::BAD_VALUE); }
              let mut result = Self::default();
              result.certificates = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod Domain {
          #![allow(non_upper_case_globals)]
          pub type Domain = i32;
          pub const App: Domain = 0;
          pub const Grant: Domain = 1;
          pub const SELinux: Domain = 2;
          pub const Blob: Domain = 3;
          pub const KeyId: Domain = 4;
          pub(crate) mod mangled { pub use super::Domain as _7_android_8_security_9_keystore2_6_Domain; }
        }
        pub mod IKeystoreOperation {
          #![allow(non_upper_case_globals)]
          #![allow(non_snake_case)]
          #[allow(unused_imports)] use binder::IBinder;
          use binder::declare_binder_interface;
          declare_binder_interface! {
            IKeystoreOperation["android.security.keystore2.IKeystoreOperation"] {
              native: BnKeystoreOperation(on_transact),
              proxy: BpKeystoreOperation {
              },
            }
          }
          pub trait IKeystoreOperation: binder::Interface {
            fn get_descriptor() -> &'static str where Self: Sized { "android.security.keystore2.IKeystoreOperation" }
            fn update(&self, _arg_input: Option<&[u8]>, _arg_aadInput: Option<&[u8]>, _arg_output: &mut Option<Vec<u8>>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn finish(&self, _arg_input: Option<&[u8]>, _arg_signature: Option<&[u8]>, _arg_entropy: Option<&[u8]>, _arg_output: &mut Option<Vec<u8>>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn abort(&self) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
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
          pub type DefaultImpl = Option<std::sync::Arc<dyn IKeystoreOperation + Send + Sync>>;
          use lazy_static::lazy_static;
          lazy_static! {
            static ref DEFAULT_IMPL: std::sync::Mutex<DefaultImpl> = std::sync::Mutex::new(None);
          }
          pub(crate) mod mangled { pub use super::IKeystoreOperation as _7_android_8_security_9_keystore2_18_IKeystoreOperation; }
          impl IKeystoreOperation for BpKeystoreOperation {
            fn update(&self, _arg_input: Option<&[u8]>, _arg_aadInput: Option<&[u8]>, _arg_output: &mut Option<Vec<u8>>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              let _aidl_reply = self.binder.transact(TRANSACTION_update, 0, |_aidl_data| {
                _aidl_data.write(&_arg_input)?;
                _aidl_data.write(&_arg_aadInput)?;
                _aidl_data.write_slice_size(_arg_output.as_deref())?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeystoreOperation>::getDefaultImpl() {
                  return _aidl_default_impl.update(_arg_input, _arg_aadInput, _arg_output);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: crate::mangled::_7_android_8_security_9_keystore2_6_Result = _aidl_reply.read()?;
              *_arg_output = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
            fn finish(&self, _arg_input: Option<&[u8]>, _arg_signature: Option<&[u8]>, _arg_entropy: Option<&[u8]>, _arg_output: &mut Option<Vec<u8>>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              let _aidl_reply = self.binder.transact(TRANSACTION_finish, 0, |_aidl_data| {
                _aidl_data.write(&_arg_input)?;
                _aidl_data.write(&_arg_signature)?;
                _aidl_data.write(&_arg_entropy)?;
                _aidl_data.write_slice_size(_arg_output.as_deref())?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeystoreOperation>::getDefaultImpl() {
                  return _aidl_default_impl.finish(_arg_input, _arg_signature, _arg_entropy, _arg_output);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: crate::mangled::_7_android_8_security_9_keystore2_6_Result = _aidl_reply.read()?;
              *_arg_output = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
            fn abort(&self) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              let _aidl_reply = self.binder.transact(TRANSACTION_abort, 0, |_aidl_data| {
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeystoreOperation>::getDefaultImpl() {
                  return _aidl_default_impl.abort();
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: crate::mangled::_7_android_8_security_9_keystore2_6_Result = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
          }
          impl IKeystoreOperation for binder::Binder<BnKeystoreOperation> {
            fn update(&self, _arg_input: Option<&[u8]>, _arg_aadInput: Option<&[u8]>, _arg_output: &mut Option<Vec<u8>>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> { self.0.update(_arg_input, _arg_aadInput, _arg_output) }
            fn finish(&self, _arg_input: Option<&[u8]>, _arg_signature: Option<&[u8]>, _arg_entropy: Option<&[u8]>, _arg_output: &mut Option<Vec<u8>>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> { self.0.finish(_arg_input, _arg_signature, _arg_entropy, _arg_output) }
            fn abort(&self) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> { self.0.abort() }
          }
          fn on_transact(_aidl_service: &dyn IKeystoreOperation, _aidl_code: binder::TransactionCode, _aidl_data: &binder::parcel::Parcel, _aidl_reply: &mut binder::parcel::Parcel) -> binder::Result<()> {
            match _aidl_code {
              TRANSACTION_update => {
                let _arg_input: Option<Vec<u8>> = _aidl_data.read()?;
                let _arg_aadInput: Option<Vec<u8>> = _aidl_data.read()?;
                let mut _arg_output: Option<Vec<u8>> = Default::default();
                _aidl_data.resize_nullable_out_vec(&mut _arg_output)?;
                let _aidl_return = _aidl_service.update(_arg_input.as_deref(), _arg_aadInput.as_deref(), &mut _arg_output);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
                    _aidl_reply.write(&_arg_output)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_finish => {
                let _arg_input: Option<Vec<u8>> = _aidl_data.read()?;
                let _arg_signature: Option<Vec<u8>> = _aidl_data.read()?;
                let _arg_entropy: Option<Vec<u8>> = _aidl_data.read()?;
                let mut _arg_output: Option<Vec<u8>> = Default::default();
                _aidl_data.resize_nullable_out_vec(&mut _arg_output)?;
                let _aidl_return = _aidl_service.finish(_arg_input.as_deref(), _arg_signature.as_deref(), _arg_entropy.as_deref(), &mut _arg_output);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
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
        pub mod IKeystoreSecurityLevel {
          #![allow(non_upper_case_globals)]
          #![allow(non_snake_case)]
          #[allow(unused_imports)] use binder::IBinder;
          use binder::declare_binder_interface;
          declare_binder_interface! {
            IKeystoreSecurityLevel["android.security.keystore2.IKeystoreSecurityLevel"] {
              native: BnKeystoreSecurityLevel(on_transact),
              proxy: BpKeystoreSecurityLevel {
              },
            }
          }
          pub trait IKeystoreSecurityLevel: binder::Interface {
            fn get_descriptor() -> &'static str where Self: Sized { "android.security.keystore2.IKeystoreSecurityLevel" }
            fn create(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_operationParameters: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_forced: bool, _arg_challenge: &mut crate::mangled::_7_android_8_security_9_keystore2_18_OperationChallenge, _arg_rc: &mut crate::mangled::_7_android_8_security_9_keystore2_6_Result) -> binder::public_api::Result<Box<dyn crate::mangled::_7_android_8_security_9_keystore2_18_IKeystoreOperation>> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn updateSubcomponent(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_publicKey: Option<&crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey>, _arg_certificateChain: Option<&crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn generateKey(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_params: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_entropy: &[u8], _arg_resultKey: &mut crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_publicKey: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey>, _arg_certificateChain: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn importKey(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_params: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_keyData: &[u8], _arg_resultKey: &mut crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_publicKey: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey>, _arg_certificateChain: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn importWrappedKey(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_wrappingKey: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_maskingKey: &[u8], _arg_params: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_authenticators: &[crate::mangled::_7_android_8_security_9_keystore2_17_AuthenticatorSpec], _arg_resultKey: &mut crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_publicKey: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey>, _arg_certificateChain: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn getDefaultImpl() -> DefaultImpl where Self: Sized {
              DEFAULT_IMPL.lock().unwrap().clone()
            }
            fn setDefaultImpl(d: DefaultImpl) -> DefaultImpl where Self: Sized {
              std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
            }
          }
          pub const TRANSACTION_create: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 0;
          pub const TRANSACTION_updateSubcomponent: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 1;
          pub const TRANSACTION_generateKey: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 2;
          pub const TRANSACTION_importKey: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 3;
          pub const TRANSACTION_importWrappedKey: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 4;
          pub type DefaultImpl = Option<std::sync::Arc<dyn IKeystoreSecurityLevel + Send + Sync>>;
          use lazy_static::lazy_static;
          lazy_static! {
            static ref DEFAULT_IMPL: std::sync::Mutex<DefaultImpl> = std::sync::Mutex::new(None);
          }
          pub(crate) mod mangled { pub use super::IKeystoreSecurityLevel as _7_android_8_security_9_keystore2_22_IKeystoreSecurityLevel; }
          impl IKeystoreSecurityLevel for BpKeystoreSecurityLevel {
            fn create(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_operationParameters: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_forced: bool, _arg_challenge: &mut crate::mangled::_7_android_8_security_9_keystore2_18_OperationChallenge, _arg_rc: &mut crate::mangled::_7_android_8_security_9_keystore2_6_Result) -> binder::public_api::Result<Box<dyn crate::mangled::_7_android_8_security_9_keystore2_18_IKeystoreOperation>> {
              let _aidl_reply = self.binder.transact(TRANSACTION_create, 0, |_aidl_data| {
                _aidl_data.write(_arg_key)?;
                _aidl_data.write(_arg_operationParameters)?;
                _aidl_data.write(&_arg_forced)?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeystoreSecurityLevel>::getDefaultImpl() {
                  return _aidl_default_impl.create(_arg_key, _arg_operationParameters, _arg_forced, _arg_challenge, _arg_rc);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: Box<dyn crate::mangled::_7_android_8_security_9_keystore2_18_IKeystoreOperation> = _aidl_reply.read()?;
              *_arg_challenge = _aidl_reply.read()?;
              *_arg_rc = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
            fn updateSubcomponent(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_publicKey: Option<&crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey>, _arg_certificateChain: Option<&crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              let _aidl_reply = self.binder.transact(TRANSACTION_updateSubcomponent, 0, |_aidl_data| {
                _aidl_data.write(_arg_key)?;
                _aidl_data.write(&_arg_publicKey)?;
                _aidl_data.write(&_arg_certificateChain)?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeystoreSecurityLevel>::getDefaultImpl() {
                  return _aidl_default_impl.updateSubcomponent(_arg_key, _arg_publicKey, _arg_certificateChain);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: crate::mangled::_7_android_8_security_9_keystore2_6_Result = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
            fn generateKey(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_params: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_entropy: &[u8], _arg_resultKey: &mut crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_publicKey: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey>, _arg_certificateChain: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              let _aidl_reply = self.binder.transact(TRANSACTION_generateKey, 0, |_aidl_data| {
                _aidl_data.write(_arg_key)?;
                _aidl_data.write(_arg_params)?;
                _aidl_data.write(_arg_entropy)?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeystoreSecurityLevel>::getDefaultImpl() {
                  return _aidl_default_impl.generateKey(_arg_key, _arg_params, _arg_entropy, _arg_resultKey, _arg_publicKey, _arg_certificateChain);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: crate::mangled::_7_android_8_security_9_keystore2_6_Result = _aidl_reply.read()?;
              *_arg_resultKey = _aidl_reply.read()?;
              *_arg_publicKey = _aidl_reply.read()?;
              *_arg_certificateChain = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
            fn importKey(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_params: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_keyData: &[u8], _arg_resultKey: &mut crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_publicKey: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey>, _arg_certificateChain: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              let _aidl_reply = self.binder.transact(TRANSACTION_importKey, 0, |_aidl_data| {
                _aidl_data.write(_arg_key)?;
                _aidl_data.write(_arg_params)?;
                _aidl_data.write(_arg_keyData)?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeystoreSecurityLevel>::getDefaultImpl() {
                  return _aidl_default_impl.importKey(_arg_key, _arg_params, _arg_keyData, _arg_resultKey, _arg_publicKey, _arg_certificateChain);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: crate::mangled::_7_android_8_security_9_keystore2_6_Result = _aidl_reply.read()?;
              *_arg_resultKey = _aidl_reply.read()?;
              *_arg_publicKey = _aidl_reply.read()?;
              *_arg_certificateChain = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
            fn importWrappedKey(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_wrappingKey: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_maskingKey: &[u8], _arg_params: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_authenticators: &[crate::mangled::_7_android_8_security_9_keystore2_17_AuthenticatorSpec], _arg_resultKey: &mut crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_publicKey: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey>, _arg_certificateChain: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              let _aidl_reply = self.binder.transact(TRANSACTION_importWrappedKey, 0, |_aidl_data| {
                _aidl_data.write(_arg_key)?;
                _aidl_data.write(_arg_wrappingKey)?;
                _aidl_data.write(_arg_maskingKey)?;
                _aidl_data.write(_arg_params)?;
                _aidl_data.write(_arg_authenticators)?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeystoreSecurityLevel>::getDefaultImpl() {
                  return _aidl_default_impl.importWrappedKey(_arg_key, _arg_wrappingKey, _arg_maskingKey, _arg_params, _arg_authenticators, _arg_resultKey, _arg_publicKey, _arg_certificateChain);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: crate::mangled::_7_android_8_security_9_keystore2_6_Result = _aidl_reply.read()?;
              *_arg_resultKey = _aidl_reply.read()?;
              *_arg_publicKey = _aidl_reply.read()?;
              *_arg_certificateChain = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
          }
          impl IKeystoreSecurityLevel for binder::Binder<BnKeystoreSecurityLevel> {
            fn create(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_operationParameters: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_forced: bool, _arg_challenge: &mut crate::mangled::_7_android_8_security_9_keystore2_18_OperationChallenge, _arg_rc: &mut crate::mangled::_7_android_8_security_9_keystore2_6_Result) -> binder::public_api::Result<Box<dyn crate::mangled::_7_android_8_security_9_keystore2_18_IKeystoreOperation>> { self.0.create(_arg_key, _arg_operationParameters, _arg_forced, _arg_challenge, _arg_rc) }
            fn updateSubcomponent(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_publicKey: Option<&crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey>, _arg_certificateChain: Option<&crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> { self.0.updateSubcomponent(_arg_key, _arg_publicKey, _arg_certificateChain) }
            fn generateKey(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_params: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_entropy: &[u8], _arg_resultKey: &mut crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_publicKey: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey>, _arg_certificateChain: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> { self.0.generateKey(_arg_key, _arg_params, _arg_entropy, _arg_resultKey, _arg_publicKey, _arg_certificateChain) }
            fn importKey(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_params: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_keyData: &[u8], _arg_resultKey: &mut crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_publicKey: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey>, _arg_certificateChain: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> { self.0.importKey(_arg_key, _arg_params, _arg_keyData, _arg_resultKey, _arg_publicKey, _arg_certificateChain) }
            fn importWrappedKey(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_wrappingKey: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_maskingKey: &[u8], _arg_params: &[crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter], _arg_authenticators: &[crate::mangled::_7_android_8_security_9_keystore2_17_AuthenticatorSpec], _arg_resultKey: &mut crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_publicKey: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey>, _arg_certificateChain: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> { self.0.importWrappedKey(_arg_key, _arg_wrappingKey, _arg_maskingKey, _arg_params, _arg_authenticators, _arg_resultKey, _arg_publicKey, _arg_certificateChain) }
          }
          fn on_transact(_aidl_service: &dyn IKeystoreSecurityLevel, _aidl_code: binder::TransactionCode, _aidl_data: &binder::parcel::Parcel, _aidl_reply: &mut binder::parcel::Parcel) -> binder::Result<()> {
            match _aidl_code {
              TRANSACTION_create => {
                let _arg_key: crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor = _aidl_data.read()?;
                let _arg_operationParameters: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter> = _aidl_data.read()?;
                let _arg_forced: bool = _aidl_data.read()?;
                let mut _arg_challenge: crate::mangled::_7_android_8_security_9_keystore2_18_OperationChallenge = Default::default();
                let mut _arg_rc: crate::mangled::_7_android_8_security_9_keystore2_6_Result = Default::default();
                let _aidl_return = _aidl_service.create(&_arg_key, &_arg_operationParameters, _arg_forced, &mut _arg_challenge, &mut _arg_rc);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
                    _aidl_reply.write(&_arg_challenge)?;
                    _aidl_reply.write(&_arg_rc)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_updateSubcomponent => {
                let _arg_key: crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor = _aidl_data.read()?;
                let _arg_publicKey: Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey> = _aidl_data.read()?;
                let _arg_certificateChain: Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain> = _aidl_data.read()?;
                let _aidl_return = _aidl_service.updateSubcomponent(&_arg_key, _arg_publicKey.as_ref(), _arg_certificateChain.as_ref());
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_generateKey => {
                let _arg_key: crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor = _aidl_data.read()?;
                let _arg_params: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter> = _aidl_data.read()?;
                let _arg_entropy: Vec<u8> = _aidl_data.read()?;
                let mut _arg_resultKey: crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor = Default::default();
                let mut _arg_publicKey: Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey> = Default::default();
                let mut _arg_certificateChain: Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain> = Default::default();
                let _aidl_return = _aidl_service.generateKey(&_arg_key, &_arg_params, &_arg_entropy, &mut _arg_resultKey, &mut _arg_publicKey, &mut _arg_certificateChain);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
                    _aidl_reply.write(&_arg_resultKey)?;
                    _aidl_reply.write(&_arg_publicKey)?;
                    _aidl_reply.write(&_arg_certificateChain)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_importKey => {
                let _arg_key: crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor = _aidl_data.read()?;
                let _arg_params: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter> = _aidl_data.read()?;
                let _arg_keyData: Vec<u8> = _aidl_data.read()?;
                let mut _arg_resultKey: crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor = Default::default();
                let mut _arg_publicKey: Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey> = Default::default();
                let mut _arg_certificateChain: Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain> = Default::default();
                let _aidl_return = _aidl_service.importKey(&_arg_key, &_arg_params, &_arg_keyData, &mut _arg_resultKey, &mut _arg_publicKey, &mut _arg_certificateChain);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
                    _aidl_reply.write(&_arg_resultKey)?;
                    _aidl_reply.write(&_arg_publicKey)?;
                    _aidl_reply.write(&_arg_certificateChain)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_importWrappedKey => {
                let _arg_key: crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor = _aidl_data.read()?;
                let _arg_wrappingKey: crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor = _aidl_data.read()?;
                let _arg_maskingKey: Vec<u8> = _aidl_data.read()?;
                let _arg_params: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter> = _aidl_data.read()?;
                let _arg_authenticators: Vec<crate::mangled::_7_android_8_security_9_keystore2_17_AuthenticatorSpec> = _aidl_data.read()?;
                let mut _arg_resultKey: crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor = Default::default();
                let mut _arg_publicKey: Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey> = Default::default();
                let mut _arg_certificateChain: Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain> = Default::default();
                let _aidl_return = _aidl_service.importWrappedKey(&_arg_key, &_arg_wrappingKey, &_arg_maskingKey, &_arg_params, &_arg_authenticators, &mut _arg_resultKey, &mut _arg_publicKey, &mut _arg_certificateChain);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
                    _aidl_reply.write(&_arg_resultKey)?;
                    _aidl_reply.write(&_arg_publicKey)?;
                    _aidl_reply.write(&_arg_certificateChain)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              _ => Err(binder::StatusCode::UNKNOWN_TRANSACTION)
            }
          }
        }
        pub mod IKeystoreService {
          #![allow(non_upper_case_globals)]
          #![allow(non_snake_case)]
          #[allow(unused_imports)] use binder::IBinder;
          use binder::declare_binder_interface;
          declare_binder_interface! {
            IKeystoreService["android.security.keystore2.IKeystoreService"] {
              native: BnKeystoreService(on_transact),
              proxy: BpKeystoreService {
              },
            }
          }
          pub trait IKeystoreService: binder::Interface {
            fn get_descriptor() -> &'static str where Self: Sized { "android.security.keystore2.IKeystoreService" }
            fn getSecurityLevel(&self, _arg_securityLevel: crate::mangled::_7_android_8_hardware_7_keymint_13_SecurityLevel, _arg_rc: &mut crate::mangled::_7_android_8_security_9_keystore2_6_Result) -> binder::public_api::Result<Box<dyn crate::mangled::_7_android_8_security_9_keystore2_22_IKeystoreSecurityLevel>> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn getKeyEntry(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_metadata: &mut crate::mangled::_7_android_8_security_9_keystore2_11_KeyMetadata, _arg_publicKey: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey>, _arg_certificateChain: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain>, _arg_rc: &mut crate::mangled::_7_android_8_security_9_keystore2_6_Result) -> binder::public_api::Result<Box<dyn crate::mangled::_7_android_8_security_9_keystore2_22_IKeystoreSecurityLevel>> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn listEntries(&self, _arg_domain: crate::mangled::_7_android_8_security_9_keystore2_6_Domain, _arg_nameSpace: i64, _arg_list: &mut Vec<crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn deleteKey(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn grant(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_granteeUid: i32, _arg_accessVector: i32, _arg_grantKey: &mut crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn ungrant(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_granteeUid: i32) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              Err(binder::StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn getDefaultImpl() -> DefaultImpl where Self: Sized {
              DEFAULT_IMPL.lock().unwrap().clone()
            }
            fn setDefaultImpl(d: DefaultImpl) -> DefaultImpl where Self: Sized {
              std::mem::replace(&mut *DEFAULT_IMPL.lock().unwrap(), d)
            }
          }
          pub const TRANSACTION_getSecurityLevel: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 0;
          pub const TRANSACTION_getKeyEntry: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 1;
          pub const TRANSACTION_listEntries: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 2;
          pub const TRANSACTION_deleteKey: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 3;
          pub const TRANSACTION_grant: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 4;
          pub const TRANSACTION_ungrant: binder::TransactionCode = binder::SpIBinder::FIRST_CALL_TRANSACTION + 5;
          pub type DefaultImpl = Option<std::sync::Arc<dyn IKeystoreService + Send + Sync>>;
          use lazy_static::lazy_static;
          lazy_static! {
            static ref DEFAULT_IMPL: std::sync::Mutex<DefaultImpl> = std::sync::Mutex::new(None);
          }
          pub(crate) mod mangled { pub use super::IKeystoreService as _7_android_8_security_9_keystore2_16_IKeystoreService; }
          impl IKeystoreService for BpKeystoreService {
            fn getSecurityLevel(&self, _arg_securityLevel: crate::mangled::_7_android_8_hardware_7_keymint_13_SecurityLevel, _arg_rc: &mut crate::mangled::_7_android_8_security_9_keystore2_6_Result) -> binder::public_api::Result<Box<dyn crate::mangled::_7_android_8_security_9_keystore2_22_IKeystoreSecurityLevel>> {
              let _aidl_reply = self.binder.transact(TRANSACTION_getSecurityLevel, 0, |_aidl_data| {
                _aidl_data.write(&_arg_securityLevel)?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeystoreService>::getDefaultImpl() {
                  return _aidl_default_impl.getSecurityLevel(_arg_securityLevel, _arg_rc);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: Box<dyn crate::mangled::_7_android_8_security_9_keystore2_22_IKeystoreSecurityLevel> = _aidl_reply.read()?;
              *_arg_rc = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
            fn getKeyEntry(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_metadata: &mut crate::mangled::_7_android_8_security_9_keystore2_11_KeyMetadata, _arg_publicKey: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey>, _arg_certificateChain: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain>, _arg_rc: &mut crate::mangled::_7_android_8_security_9_keystore2_6_Result) -> binder::public_api::Result<Box<dyn crate::mangled::_7_android_8_security_9_keystore2_22_IKeystoreSecurityLevel>> {
              let _aidl_reply = self.binder.transact(TRANSACTION_getKeyEntry, 0, |_aidl_data| {
                _aidl_data.write(_arg_key)?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeystoreService>::getDefaultImpl() {
                  return _aidl_default_impl.getKeyEntry(_arg_key, _arg_metadata, _arg_publicKey, _arg_certificateChain, _arg_rc);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: Box<dyn crate::mangled::_7_android_8_security_9_keystore2_22_IKeystoreSecurityLevel> = _aidl_reply.read()?;
              *_arg_metadata = _aidl_reply.read()?;
              *_arg_publicKey = _aidl_reply.read()?;
              *_arg_certificateChain = _aidl_reply.read()?;
              *_arg_rc = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
            fn listEntries(&self, _arg_domain: crate::mangled::_7_android_8_security_9_keystore2_6_Domain, _arg_nameSpace: i64, _arg_list: &mut Vec<crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              let _aidl_reply = self.binder.transact(TRANSACTION_listEntries, 0, |_aidl_data| {
                _aidl_data.write(&_arg_domain)?;
                _aidl_data.write(&_arg_nameSpace)?;
                _aidl_data.write_slice_size(Some(_arg_list))?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeystoreService>::getDefaultImpl() {
                  return _aidl_default_impl.listEntries(_arg_domain, _arg_nameSpace, _arg_list);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: crate::mangled::_7_android_8_security_9_keystore2_6_Result = _aidl_reply.read()?;
              *_arg_list = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
            fn deleteKey(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              let _aidl_reply = self.binder.transact(TRANSACTION_deleteKey, 0, |_aidl_data| {
                _aidl_data.write(_arg_key)?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeystoreService>::getDefaultImpl() {
                  return _aidl_default_impl.deleteKey(_arg_key);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: crate::mangled::_7_android_8_security_9_keystore2_6_Result = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
            fn grant(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_granteeUid: i32, _arg_accessVector: i32, _arg_grantKey: &mut crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              let _aidl_reply = self.binder.transact(TRANSACTION_grant, 0, |_aidl_data| {
                _aidl_data.write(_arg_key)?;
                _aidl_data.write(&_arg_granteeUid)?;
                _aidl_data.write(&_arg_accessVector)?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeystoreService>::getDefaultImpl() {
                  return _aidl_default_impl.grant(_arg_key, _arg_granteeUid, _arg_accessVector, _arg_grantKey);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: crate::mangled::_7_android_8_security_9_keystore2_6_Result = _aidl_reply.read()?;
              *_arg_grantKey = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
            fn ungrant(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_granteeUid: i32) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> {
              let _aidl_reply = self.binder.transact(TRANSACTION_ungrant, 0, |_aidl_data| {
                _aidl_data.write(_arg_key)?;
                _aidl_data.write(&_arg_granteeUid)?;
                Ok(())
              });
              if let Err(binder::StatusCode::UNKNOWN_TRANSACTION) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IKeystoreService>::getDefaultImpl() {
                  return _aidl_default_impl.ungrant(_arg_key, _arg_granteeUid);
                }
              }
              let _aidl_reply = _aidl_reply?;
              let _aidl_status: binder::Status = _aidl_reply.read()?;
              if !_aidl_status.is_ok() { return Err(_aidl_status); }
              let _aidl_return: crate::mangled::_7_android_8_security_9_keystore2_6_Result = _aidl_reply.read()?;
              Ok(_aidl_return)
            }
          }
          impl IKeystoreService for binder::Binder<BnKeystoreService> {
            fn getSecurityLevel(&self, _arg_securityLevel: crate::mangled::_7_android_8_hardware_7_keymint_13_SecurityLevel, _arg_rc: &mut crate::mangled::_7_android_8_security_9_keystore2_6_Result) -> binder::public_api::Result<Box<dyn crate::mangled::_7_android_8_security_9_keystore2_22_IKeystoreSecurityLevel>> { self.0.getSecurityLevel(_arg_securityLevel, _arg_rc) }
            fn getKeyEntry(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_metadata: &mut crate::mangled::_7_android_8_security_9_keystore2_11_KeyMetadata, _arg_publicKey: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey>, _arg_certificateChain: &mut Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain>, _arg_rc: &mut crate::mangled::_7_android_8_security_9_keystore2_6_Result) -> binder::public_api::Result<Box<dyn crate::mangled::_7_android_8_security_9_keystore2_22_IKeystoreSecurityLevel>> { self.0.getKeyEntry(_arg_key, _arg_metadata, _arg_publicKey, _arg_certificateChain, _arg_rc) }
            fn listEntries(&self, _arg_domain: crate::mangled::_7_android_8_security_9_keystore2_6_Domain, _arg_nameSpace: i64, _arg_list: &mut Vec<crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor>) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> { self.0.listEntries(_arg_domain, _arg_nameSpace, _arg_list) }
            fn deleteKey(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> { self.0.deleteKey(_arg_key) }
            fn grant(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_granteeUid: i32, _arg_accessVector: i32, _arg_grantKey: &mut crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> { self.0.grant(_arg_key, _arg_granteeUid, _arg_accessVector, _arg_grantKey) }
            fn ungrant(&self, _arg_key: &crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, _arg_granteeUid: i32) -> binder::public_api::Result<crate::mangled::_7_android_8_security_9_keystore2_6_Result> { self.0.ungrant(_arg_key, _arg_granteeUid) }
          }
          fn on_transact(_aidl_service: &dyn IKeystoreService, _aidl_code: binder::TransactionCode, _aidl_data: &binder::parcel::Parcel, _aidl_reply: &mut binder::parcel::Parcel) -> binder::Result<()> {
            match _aidl_code {
              TRANSACTION_getSecurityLevel => {
                let _arg_securityLevel: crate::mangled::_7_android_8_hardware_7_keymint_13_SecurityLevel = _aidl_data.read()?;
                let mut _arg_rc: crate::mangled::_7_android_8_security_9_keystore2_6_Result = Default::default();
                let _aidl_return = _aidl_service.getSecurityLevel(_arg_securityLevel, &mut _arg_rc);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
                    _aidl_reply.write(&_arg_rc)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_getKeyEntry => {
                let _arg_key: crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor = _aidl_data.read()?;
                let mut _arg_metadata: crate::mangled::_7_android_8_security_9_keystore2_11_KeyMetadata = Default::default();
                let mut _arg_publicKey: Option<crate::mangled::_7_android_8_security_9_keystore2_9_PublicKey> = Default::default();
                let mut _arg_certificateChain: Option<crate::mangled::_7_android_8_security_9_keystore2_16_CertificateChain> = Default::default();
                let mut _arg_rc: crate::mangled::_7_android_8_security_9_keystore2_6_Result = Default::default();
                let _aidl_return = _aidl_service.getKeyEntry(&_arg_key, &mut _arg_metadata, &mut _arg_publicKey, &mut _arg_certificateChain, &mut _arg_rc);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
                    _aidl_reply.write(&_arg_metadata)?;
                    _aidl_reply.write(&_arg_publicKey)?;
                    _aidl_reply.write(&_arg_certificateChain)?;
                    _aidl_reply.write(&_arg_rc)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_listEntries => {
                let _arg_domain: crate::mangled::_7_android_8_security_9_keystore2_6_Domain = _aidl_data.read()?;
                let _arg_nameSpace: i64 = _aidl_data.read()?;
                let mut _arg_list: Vec<crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor> = Default::default();
                _aidl_data.resize_out_vec(&mut _arg_list)?;
                let _aidl_return = _aidl_service.listEntries(_arg_domain, _arg_nameSpace, &mut _arg_list);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
                    _aidl_reply.write(&_arg_list)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_deleteKey => {
                let _arg_key: crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor = _aidl_data.read()?;
                let _aidl_return = _aidl_service.deleteKey(&_arg_key);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_grant => {
                let _arg_key: crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor = _aidl_data.read()?;
                let _arg_granteeUid: i32 = _aidl_data.read()?;
                let _arg_accessVector: i32 = _aidl_data.read()?;
                let mut _arg_grantKey: crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor = Default::default();
                let _aidl_return = _aidl_service.grant(&_arg_key, _arg_granteeUid, _arg_accessVector, &mut _arg_grantKey);
                match &_aidl_return {
                  Ok(_aidl_return) => {
                    _aidl_reply.write(&binder::Status::from(binder::StatusCode::OK))?;
                    _aidl_reply.write(_aidl_return)?;
                    _aidl_reply.write(&_arg_grantKey)?;
                  }
                  Err(_aidl_status) => _aidl_reply.write(_aidl_status)?
                }
                Ok(())
              }
              TRANSACTION_ungrant => {
                let _arg_key: crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor = _aidl_data.read()?;
                let _arg_granteeUid: i32 = _aidl_data.read()?;
                let _aidl_return = _aidl_service.ungrant(&_arg_key, _arg_granteeUid);
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
        pub mod KeyDescriptor {
          pub struct KeyDescriptor {
            pub domain: crate::mangled::_7_android_8_security_9_keystore2_6_Domain, 
            pub namespace_: i64, 
            pub alias: Option<String>,
            pub blob: Option<Vec<u8>>,
          }
          pub(crate) mod mangled { pub use super::KeyDescriptor as _7_android_8_security_9_keystore2_13_KeyDescriptor; }
          impl Default for KeyDescriptor {
            fn default() -> Self {
              Self {
                domain: Default::default(),
                namespace_: 0,
                alias: Default::default(),
                blob: Default::default(),
              }
            }
          }
          impl binder::parcel::Serialize for KeyDescriptor {
            fn serialize(&self, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              <Self as binder::parcel::SerializeOption>::serialize_option(Some(self), parcel)
            }
          }
          impl binder::parcel::SerializeArray for KeyDescriptor {}
          impl binder::parcel::SerializeOption for KeyDescriptor {
            fn serialize_option(this: Option<&Self>, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              let this = if let Some(this) = this {
                parcel.write(&1i32)?;
                this
              } else {
                return parcel.write(&0i32);
              };
              let start_pos = parcel.get_data_position();
              parcel.write(&0i32)?;
              parcel.write(&this.domain)?;
              parcel.write(&this.namespace_)?;
              parcel.write(&this.alias)?;
              parcel.write(&this.blob)?;
              let end_pos = parcel.get_data_position();
              let parcelable_size = (end_pos - start_pos) as i32;
              unsafe { parcel.set_data_position(start_pos)?; }
              parcel.write(&parcelable_size)?;
              unsafe { parcel.set_data_position(end_pos)?; }
              Ok(())
            }
          }
          impl binder::parcel::Deserialize for KeyDescriptor {
            fn deserialize(parcel: &binder::parcel::Parcel) -> binder::Result<Self> {
              <Self as binder::parcel::DeserializeOption>::deserialize_option(parcel)
                 .transpose()
                 .unwrap_or(Err(binder::StatusCode::UNEXPECTED_NULL))
            }
          }
          impl binder::parcel::DeserializeArray for KeyDescriptor {}
          impl binder::parcel::DeserializeOption for KeyDescriptor {
            fn deserialize_option(parcel: &binder::parcel::Parcel) -> binder::Result<Option<Self>> {
              let status: i32 = parcel.read()?;
              if status == 0 { return Ok(None); }
              let start_pos = parcel.get_data_position();
              let parcelable_size: i32 = parcel.read()?;
              if parcelable_size < 0 { return Err(binder::StatusCode::BAD_VALUE); }
              let mut result = Self::default();
              result.domain = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.namespace_ = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.alias = parcel.read()?;
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
        pub mod KeyMetadata {
          pub struct KeyMetadata {
            pub key: crate::mangled::_7_android_8_security_9_keystore2_13_KeyDescriptor, 
            pub securityLevel: crate::mangled::_7_android_8_hardware_7_keymint_13_SecurityLevel, 
            pub hardwareEnforced: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter>, 
            pub softwareEnforced: Vec<crate::mangled::_7_android_8_hardware_7_keymint_12_KeyParameter>, 
          }
          pub(crate) mod mangled { pub use super::KeyMetadata as _7_android_8_security_9_keystore2_11_KeyMetadata; }
          impl Default for KeyMetadata {
            fn default() -> Self {
              Self {
                key: Default::default(),
                securityLevel: Default::default(),
                hardwareEnforced: Default::default(),
                softwareEnforced: Default::default(),
              }
            }
          }
          impl binder::parcel::Serialize for KeyMetadata {
            fn serialize(&self, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              <Self as binder::parcel::SerializeOption>::serialize_option(Some(self), parcel)
            }
          }
          impl binder::parcel::SerializeArray for KeyMetadata {}
          impl binder::parcel::SerializeOption for KeyMetadata {
            fn serialize_option(this: Option<&Self>, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              let this = if let Some(this) = this {
                parcel.write(&1i32)?;
                this
              } else {
                return parcel.write(&0i32);
              };
              let start_pos = parcel.get_data_position();
              parcel.write(&0i32)?;
              parcel.write(&this.key)?;
              parcel.write(&this.securityLevel)?;
              parcel.write(&this.hardwareEnforced)?;
              parcel.write(&this.softwareEnforced)?;
              let end_pos = parcel.get_data_position();
              let parcelable_size = (end_pos - start_pos) as i32;
              unsafe { parcel.set_data_position(start_pos)?; }
              parcel.write(&parcelable_size)?;
              unsafe { parcel.set_data_position(end_pos)?; }
              Ok(())
            }
          }
          impl binder::parcel::Deserialize for KeyMetadata {
            fn deserialize(parcel: &binder::parcel::Parcel) -> binder::Result<Self> {
              <Self as binder::parcel::DeserializeOption>::deserialize_option(parcel)
                 .transpose()
                 .unwrap_or(Err(binder::StatusCode::UNEXPECTED_NULL))
            }
          }
          impl binder::parcel::DeserializeArray for KeyMetadata {}
          impl binder::parcel::DeserializeOption for KeyMetadata {
            fn deserialize_option(parcel: &binder::parcel::Parcel) -> binder::Result<Option<Self>> {
              let status: i32 = parcel.read()?;
              if status == 0 { return Ok(None); }
              let start_pos = parcel.get_data_position();
              let parcelable_size: i32 = parcel.read()?;
              if parcelable_size < 0 { return Err(binder::StatusCode::BAD_VALUE); }
              let mut result = Self::default();
              result.key = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.securityLevel = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.hardwareEnforced = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.softwareEnforced = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod KeyPermission {
          #![allow(non_upper_case_globals)]
          pub type KeyPermission = i32;
          pub const None: KeyPermission = 0;
          pub const Delete: KeyPermission = 1;
          pub const GenUniqueId: KeyPermission = 2;
          pub const GetInfo: KeyPermission = 4;
          pub const Grant: KeyPermission = 8;
          pub const List: KeyPermission = 16;
          pub const ManageBlob: KeyPermission = 32;
          pub const Rebind: KeyPermission = 64;
          pub const ReqForcedOp: KeyPermission = 128;
          pub const Update: KeyPermission = 256;
          pub const Use: KeyPermission = 512;
          pub const UseDevId: KeyPermission = 1024;
          pub(crate) mod mangled { pub use super::KeyPermission as _7_android_8_security_9_keystore2_13_KeyPermission; }
        }
        pub mod OperationChallenge {
          pub struct OperationChallenge {
            pub challenge: i64, 
          }
          pub(crate) mod mangled { pub use super::OperationChallenge as _7_android_8_security_9_keystore2_18_OperationChallenge; }
          impl Default for OperationChallenge {
            fn default() -> Self {
              Self {
                challenge: 0,
              }
            }
          }
          impl binder::parcel::Serialize for OperationChallenge {
            fn serialize(&self, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              <Self as binder::parcel::SerializeOption>::serialize_option(Some(self), parcel)
            }
          }
          impl binder::parcel::SerializeArray for OperationChallenge {}
          impl binder::parcel::SerializeOption for OperationChallenge {
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
              let end_pos = parcel.get_data_position();
              let parcelable_size = (end_pos - start_pos) as i32;
              unsafe { parcel.set_data_position(start_pos)?; }
              parcel.write(&parcelable_size)?;
              unsafe { parcel.set_data_position(end_pos)?; }
              Ok(())
            }
          }
          impl binder::parcel::Deserialize for OperationChallenge {
            fn deserialize(parcel: &binder::parcel::Parcel) -> binder::Result<Self> {
              <Self as binder::parcel::DeserializeOption>::deserialize_option(parcel)
                 .transpose()
                 .unwrap_or(Err(binder::StatusCode::UNEXPECTED_NULL))
            }
          }
          impl binder::parcel::DeserializeArray for OperationChallenge {}
          impl binder::parcel::DeserializeOption for OperationChallenge {
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
              Ok(Some(result))
            }
          }
        }
        pub mod PublicKey {
          pub struct PublicKey {
            pub keyMaterial: Vec<u8>, 
          }
          pub(crate) mod mangled { pub use super::PublicKey as _7_android_8_security_9_keystore2_9_PublicKey; }
          impl Default for PublicKey {
            fn default() -> Self {
              Self {
                keyMaterial: Default::default(),
              }
            }
          }
          impl binder::parcel::Serialize for PublicKey {
            fn serialize(&self, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              <Self as binder::parcel::SerializeOption>::serialize_option(Some(self), parcel)
            }
          }
          impl binder::parcel::SerializeArray for PublicKey {}
          impl binder::parcel::SerializeOption for PublicKey {
            fn serialize_option(this: Option<&Self>, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              let this = if let Some(this) = this {
                parcel.write(&1i32)?;
                this
              } else {
                return parcel.write(&0i32);
              };
              let start_pos = parcel.get_data_position();
              parcel.write(&0i32)?;
              parcel.write(&this.keyMaterial)?;
              let end_pos = parcel.get_data_position();
              let parcelable_size = (end_pos - start_pos) as i32;
              unsafe { parcel.set_data_position(start_pos)?; }
              parcel.write(&parcelable_size)?;
              unsafe { parcel.set_data_position(end_pos)?; }
              Ok(())
            }
          }
          impl binder::parcel::Deserialize for PublicKey {
            fn deserialize(parcel: &binder::parcel::Parcel) -> binder::Result<Self> {
              <Self as binder::parcel::DeserializeOption>::deserialize_option(parcel)
                 .transpose()
                 .unwrap_or(Err(binder::StatusCode::UNEXPECTED_NULL))
            }
          }
          impl binder::parcel::DeserializeArray for PublicKey {}
          impl binder::parcel::DeserializeOption for PublicKey {
            fn deserialize_option(parcel: &binder::parcel::Parcel) -> binder::Result<Option<Self>> {
              let status: i32 = parcel.read()?;
              if status == 0 { return Ok(None); }
              let start_pos = parcel.get_data_position();
              let parcelable_size: i32 = parcel.read()?;
              if parcelable_size < 0 { return Err(binder::StatusCode::BAD_VALUE); }
              let mut result = Self::default();
              result.keyMaterial = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              Ok(Some(result))
            }
          }
        }
        pub mod ResponseCode {
          #![allow(non_upper_case_globals)]
          pub type ResponseCode = i32;
          pub const Ok: ResponseCode = 0;
          pub const Locked: ResponseCode = 2;
          pub const Uninitialized: ResponseCode = 3;
          pub const SystemError: ResponseCode = 4;
          pub const PermissionDenied: ResponseCode = 6;
          pub const KeyNotFound: ResponseCode = 7;
          pub const ValueCorrupted: ResponseCode = 8;
          pub const WrongPassword: ResponseCode = 10;
          pub const OpAuthNeeded: ResponseCode = 15;
          pub const KeyPermanentlyInvalidated: ResponseCode = 17;
          pub const NoSuchSecurityLevel: ResponseCode = 18;
          pub const KeymintErrorCode: ResponseCode = 19;
          pub const BackendBusy: ResponseCode = 20;
          pub(crate) mod mangled { pub use super::ResponseCode as _7_android_8_security_9_keystore2_12_ResponseCode; }
        }
        pub mod Result {
          #[derive(Debug, Copy, Clone, Eq, PartialEq)]
          pub struct Result {
            pub rc: crate::mangled::_7_android_8_security_9_keystore2_12_ResponseCode, 
            pub errorCode: crate::mangled::_7_android_8_hardware_7_keymint_9_ErrorCode, 
          }
          pub(crate) mod mangled { pub use super::Result as _7_android_8_security_9_keystore2_6_Result; }
          impl Default for Result {
            fn default() -> Self {
              Self {
                rc: Default::default(),
                errorCode: Default::default(),
              }
            }
          }
          impl binder::parcel::Serialize for Result {
            fn serialize(&self, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              <Self as binder::parcel::SerializeOption>::serialize_option(Some(self), parcel)
            }
          }
          impl binder::parcel::SerializeArray for Result {}
          impl binder::parcel::SerializeOption for Result {
            fn serialize_option(this: Option<&Self>, parcel: &mut binder::parcel::Parcel) -> binder::Result<()> {
              let this = if let Some(this) = this {
                parcel.write(&1i32)?;
                this
              } else {
                return parcel.write(&0i32);
              };
              let start_pos = parcel.get_data_position();
              parcel.write(&0i32)?;
              parcel.write(&this.rc)?;
              parcel.write(&this.errorCode)?;
              let end_pos = parcel.get_data_position();
              let parcelable_size = (end_pos - start_pos) as i32;
              unsafe { parcel.set_data_position(start_pos)?; }
              parcel.write(&parcelable_size)?;
              unsafe { parcel.set_data_position(end_pos)?; }
              Ok(())
            }
          }
          impl binder::parcel::Deserialize for Result {
            fn deserialize(parcel: &binder::parcel::Parcel) -> binder::Result<Self> {
              <Self as binder::parcel::DeserializeOption>::deserialize_option(parcel)
                 .transpose()
                 .unwrap_or(Err(binder::StatusCode::UNEXPECTED_NULL))
            }
          }
          impl binder::parcel::DeserializeArray for Result {}
          impl binder::parcel::DeserializeOption for Result {
            fn deserialize_option(parcel: &binder::parcel::Parcel) -> binder::Result<Option<Self>> {
              let status: i32 = parcel.read()?;
              if status == 0 { return Ok(None); }
              let start_pos = parcel.get_data_position();
              let parcelable_size: i32 = parcel.read()?;
              if parcelable_size < 0 { return Err(binder::StatusCode::BAD_VALUE); }
              let mut result = Self::default();
              result.rc = parcel.read()?;
              if (parcel.get_data_position() - start_pos) >= parcelable_size {
                unsafe { parcel.set_data_position(start_pos + parcelable_size)?; }
                return Ok(Some(result));
              }
              result.errorCode = parcel.read()?;
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
  pub use super::aidl::android::security::keystore2::AuthenticatorSpec::mangled::*;
  pub use super::aidl::android::security::keystore2::Certificate::mangled::*;
  pub use super::aidl::android::security::keystore2::CertificateChain::mangled::*;
  pub use super::aidl::android::security::keystore2::Domain::mangled::*;
  pub use super::aidl::android::security::keystore2::IKeystoreOperation::mangled::*;
  pub use super::aidl::android::security::keystore2::IKeystoreSecurityLevel::mangled::*;
  pub use super::aidl::android::security::keystore2::IKeystoreService::mangled::*;
  pub use super::aidl::android::security::keystore2::KeyDescriptor::mangled::*;
  pub use super::aidl::android::security::keystore2::KeyMetadata::mangled::*;
  pub use super::aidl::android::security::keystore2::KeyPermission::mangled::*;
  pub use super::aidl::android::security::keystore2::OperationChallenge::mangled::*;
  pub use super::aidl::android::security::keystore2::PublicKey::mangled::*;
  pub use super::aidl::android::security::keystore2::ResponseCode::mangled::*;
  pub use super::aidl::android::security::keystore2::Result::mangled::*;
  pub(crate) use android_hardware_keymint::mangled::*;
}
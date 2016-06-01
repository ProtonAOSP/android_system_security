// Copyright 2016 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef KEYSTORE_INCLUDE_KEYSTORE_KEYATTESTATIONPACKAGEINFO_H_
#define KEYSTORE_INCLUDE_KEYSTORE_KEYATTESTATIONPACKAGEINFO_H_

#include "Signature.h"
#include "utils.h"
#include <binder/Parcelable.h>
#include <memory>
#include <stdint.h>
#include <vector>

namespace android {
namespace security {
namespace keymaster {

class KeyAttestationPackageInfo : public Parcelable {
  public:
    typedef SharedNullableIterator<const content::pm::Signature, std::vector>
        ConstSignatureIterator;

    status_t writeToParcel(Parcel*) const override;
    status_t readFromParcel(const Parcel* parcel) override;

    const std::unique_ptr<String16>& package_name() const { return packageName_; }
    int32_t version_code() const { return versionCode_; }

    ConstSignatureIterator sigs_begin() const { return ConstSignatureIterator(signatures_); }
    ConstSignatureIterator sigs_end() const { return ConstSignatureIterator(); }

  private:
    std::unique_ptr<String16> packageName_;
    int32_t versionCode_;
    std::shared_ptr<std::vector<std::unique_ptr<content::pm::Signature>>> signatures_;
};

}  // namespace keymaster
}  // namespace security
}  // namespace android

#endif  // KEYSTORE_INCLUDE_KEYSTORE_KEYATTESTATIONPACKAGEINFO_H_

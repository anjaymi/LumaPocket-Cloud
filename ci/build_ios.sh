#!/bin/bash
set -euo pipefail
RUST_VERSION=$(python3 -c 'import json; print(json.load(open("build.json"))["rustVersion"])')
rustup toolchain install "$RUST_VERSION" --profile minimal
rustup target add aarch64-apple-ios --toolchain "$RUST_VERSION"
# Scope the iPhone SDK to the cross compiler; CocoaPods runs macOS host tools.

(cd "$LUMAPOCKET_WORKSPACE/rust-core" && SDKROOT="$(xcrun --sdk iphoneos --show-sdk-path)" IPHONEOS_DEPLOYMENT_TARGET=15.0 cargo "+$RUST_VERSION" build --locked --release --target aarch64-apple-ios -p nai_core_tokenizer)
mkdir -p "$LUMAPOCKET_APP/ios/Native"
cp "$LUMAPOCKET_WORKSPACE/rust-core/target/aarch64-apple-ios/release/libnai_core_tokenizer.a" "$LUMAPOCKET_APP/ios/Native/"
ruby ci/configure_ios.rb
cd "$LUMAPOCKET_APP"
flutter --no-version-check pub get --enforce-lockfile
flutter --no-version-check analyze --no-pub --no-fatal-warnings --no-fatal-infos lib
flutter --no-version-check build ios --release --no-codesign --no-pub --dart-define=NAI4_APP_VERSION="$(python3 -c 'import re; print(re.search(r"^version: ([^+]+)", open("pubspec.yaml").read(), re.M).group(1))')"
cd "$GITHUB_WORKSPACE"
python3 ci/package_ipa.py

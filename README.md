# LumaPocket

A personal iOS build workspace. This repository contains only the build workflow,
its tooling, and an encrypted source snapshot. The primary project and its Git
history are not published here.

## Build for your own iPhone

1. Open **Actions → iOS self-test → Run workflow**.
2. Download the successful run's artifact. It contains an unsigned `.ipa`, its
   SHA-256 checksum, and a build verification report.
3. Sign and install the IPA on Windows using your own Apple account in
   [Sideloadly](https://sideloadly.io/).

Free Apple account signatures normally need refreshing every seven days.
The workflow does not require an Apple ID, developer certificate, or App Store
Connect access. It does not publish to TestFlight or the App Store.

The source snapshot is encrypted with GPG AES-256. Its passphrase is held in the
repository secret `BUILD_SOURCE_PASSPHRASE`, available only to trusted builds.
Fork and pull-request builds do not run this workflow. Artifacts expire after
seven days; run it again when needed.

## Free personal signing for friends

[Setup and current limits](signing/README.md). Each tester uses their own Apple
account and a separate public GitHub repository with its own encryption key.
Run `signing\start.cmd` on Windows to create/select your personal repository and
authorize locally. Daily signing stays disabled until the first cloud signature
for that authorization is verified. Device installation/refresh is still required.

Unsigned builds are shared through public Releases; personal signing certificates,
sessions and signed packages are encrypted in each tester's repository. Testers do
not need access to the encrypted application source or its build secret.

## Self-test scope

The ARM64 release build and exported offline-tokenizer symbols are checked by CI.
Physical iPhone testing is still required. The current file-selector plugin does
not provide save-location or directory dialogs on iOS. Generated images remain in
the application's Documents folder, exposed through the iOS Files app for this
self-test build.

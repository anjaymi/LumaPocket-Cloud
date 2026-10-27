require 'json'
require 'xcodeproj'

config = JSON.parse(File.read(File.join(ENV.fetch('GITHUB_WORKSPACE'), 'build.json')))
app = ENV.fetch('LUMAPOCKET_APP')
project = Xcodeproj::Project.open(File.join(app, 'ios/Runner.xcodeproj'))
project.targets.each do |target|
  target.build_configurations.each do |build|
    build.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = config.fetch('minimumIOSVersion')
    next unless target.name == 'Runner'
    build.build_settings['PRODUCT_BUNDLE_IDENTIFIER'] = config.fetch('bundleIdentifier')
    build.build_settings['CODE_SIGNING_ALLOWED'] = 'NO'
    build.build_settings['DEVELOPMENT_TEAM'] = ''
    build.build_settings['OTHER_LDFLAGS'] = [
      '$(inherited)', '-force_load', '$(SRCROOT)/Native/libnai_core_tokenizer.a',
      '-Wl,-u,_nai_qwen_count_json', '-Wl,-u,_nai_qwen_count_free',
      '-Wl,-export_dynamic', '-liconv', '-lc++',
      '-framework', 'Security', '-framework', 'SystemConfiguration',
      '-framework', 'CoreFoundation'
    ]
  end
end
project.save
info = File.join(app, 'ios/Runner/Info.plist')
plist = Xcodeproj::Plist.read_from_path(info)
plist['CFBundleDisplayName'] = config.fetch('displayName')
plist['NSPhotoLibraryUsageDescription'] = '选择参考图片或导入图片。'
plist['NSPhotoLibraryAddUsageDescription'] = '保存生成的图片到相册。'
plist['NSCameraUsageDescription'] = '拍摄参考图片。'
plist['NSLocalNetworkUsageDescription'] = '与同一网络中的设备传输图片。'
plist['LSSupportsOpeningDocumentsInPlace'] = true
plist['UIFileSharingEnabled'] = true
plist['NSAppTransportSecurity'] = { 'NSAllowsLocalNetworking' => true }
Xcodeproj::Plist.write_to_path(plist, info)

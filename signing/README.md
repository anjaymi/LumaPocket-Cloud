# 免费多人 GitHub 重签实验

每人使用自己的 Apple 账号和自己的 GitHub 仓库。Windows 完成首次授权后，由 GitHub
的 Mac 执行器检查到期时间并生成签名包，无需准备 Mac。工具测试不代表 Apple 已实际
签发可用的描述文件，也不代表已经完成真机安装；这仍是实验链路。

## 朋友首次使用

Windows 需要 Python 3.9+、Git for Windows、GitHub CLI 和 Visual C++ 2015–2022
x64 运行库。启动器优先使用本机已有的 Codex Python，其他电脑使用 PATH 中的 Python。
已附带校验过的 Swift 6.0.3 便携库，无需安装完整 Swift SDK。

先在自己的电脑登录自己的个人 GitHub 账号：

```bat
gh auth login --hostname github.com --scopes repo,workflow
git clone https://github.com/anjaymi/LumaPocket.git
cd LumaPocket
signing\start.cmd
```

也可下载仓库 ZIP、解压后双击 `signing\start.cmd`。默认执行 `onboard`，依次：

1. 创建或选择 `你的用户名/LumaPocket-Cloud` 公开仓库。
2. 核对仓库归属，并配置仓库数字 ID 和账号数字 ID。
3. 本机输入 iPhone／iPad 的 UDID、Apple 登录邮箱、密码和验证码。
4. 创建或复用证书、登记设备，保存加密会话。
5. 把该用户的独立密钥和加密状态写入其个人仓库 Secrets。
6. 运行首轮手动重签，验证当前授权的签名包后才开启每日检查。

Apple 密码由本机 SideSign 交互提示读取，不作为脚本参数，也不保存到 GitHub Secrets。
UDID 不是设备序列号。本实验仅支持账号中恰好有一个免费 Personal Team 的情况。

想分步执行：

```bat
signing\start.cmd setup
signing\start.cmd authorize
```

免费初始化只接受公开的个人仓库，默认分支须为 `main`，使用 GitHub 标准托管执行器。
原始仓库负责应用构建；朋友无需应用源码解密密钥或 `BUILD_SOURCE_PASSPHRASE`。

## 隔离方式

- 每人独立仓库：Secrets、签名任务和产物位于各自仓库。
- 每个仓库生成独立随机密钥，本机目录按 GitHub 账号 ID／仓库 ID 区分。
- 加密授权绑定仓库数字 ID、GitHub 主人数字 ID 和 Apple 账号摘要。串用授权文件、
  重建同名仓库或换 Apple 账号时，会拒绝直接复用。
- 云端仅接受仓库主人在 `main` 上的重签；PR 不触发重签。本机固定使用该主人的
  GitHub 凭据，避免另一窗口切换登录时串号。
- 同一仓库的云端任务串行执行，同一本机授权目录有进程锁。
- 公开共享的只有带哈希校验的未签名构建。个人证书、会话、设备信息和签名 IPA
  均加密保存；公开报告只含版本、有效期、GitHub 归属和验证结果。

隔离边界是个人 GitHub 仓库和本机操作系统用户。仓库管理员能修改该仓库的工作流，
因此应由每人自行管理仓库。多人共用同一个 Windows 登录用户，不能形成操作系统级
密钥隔离，应各用自己的 Windows 账户。本机密钥由当前 Windows 用户的 DPAPI 保护。

## 自动检查与应用更新

每天约 **香港时间 10:37** 检查，描述文件剩余不超过 **48 小时** 时尝试重签。
个人仓库从原始仓库的公开 Release 获取未签名包，校验仓库 ID、发布者、构建来源、
大小和 SHA-256。新构建发布后，后续任务会获取新的应用版本。

签名时核对团队、App ID、设备 UDID、证书和有效期，再用 Apple 的 `codesign` 验证
完整性、ARM64 架构和离线分词符号。不会把未延长有效期的旧描述文件当成续签成功。
登录失效、Apple 要求验证码或证书需要更换时，需本人回到本机处理并重新授权。
脚本不会自动撤销其他应用的证书。每个用户仍需完成首次真实签名和真机安装验证。

GitHub 定时任务可能延迟；公开仓库连续 60 天无活动，定时工作流可能停用。
在有有效验证结果时，`enable` 会重新启用工作流。若签名已过期，先重新授权／验证。
本项目不通过制造无意义提交绕过该限制。

## 下载与安装

```bat
signing\start.cmd download
```

脚本校验仓库归属、签名报告和 IPA 哈希，解密到自己的本机目录：

```text
.lumapocket-signing/profiles/<GitHub账号ID>/<仓库ID>/LumaPocket_<版本>_signed.ipa
```

请保留整个私有目录。签名包仍需安装／刷新到登记的 iPhone／iPad，云端不会直接修改
设备上已安装应用的签名。免费描述文件仍受 Apple 的七天有效期限制。
例如，在已配对的电脑上，可通过保持现有签名的工具安装现成 IPA：

```text
python -m pymobiledevice3 apps install --udid YOUR_UDID PATH_TO_SIGNED_IPA
```

该安装依赖不自动安装；本项目尚未完成实际 iPhone／iPad 安装测试。
若安装工具重新签名，会改变本实验已验证的签名身份。

## 恢复、停用与第二个账号

本机授权已保存，但上传状态时断网，直接重试即可：

```bat
signing\start.cmd publish
```

首轮手动任务成功后，可以开启检查或停用：

```bat
signing\start.cmd enable
signing\start.cmd disable
```

同一个 GitHub 用户使用第二个 Apple 账号，应创建第二个仓库：

```bat
signing\start.cmd setup --repo-name LumaPocket-Second
signing\start.cmd authorize
```

切回已初始化的仓库，可以指定：

```bat
signing\start.cmd download --repo YOUR_LOGIN/LumaPocket-Cloud
```

切换 GitHub 登录后，须为新用户执行自己的 `setup`，不会自动选择前一个人的状态。
旧单人版根目录下的授权文件会保留，新版不会自动把它迁入任何用户仓库。
请关闭旧授权窗口，用新版入口初始化；旧证书若占用名额，需本人先处理后再继续。

## 验证与来源

`Free signing experiment` 的验证模式在 Windows／macOS 运行无 Apple 账号的工具、
隔离、GPG／DPAPI、真实 CSR／PKCS#12 测试。Mac 还使用当前仓库的只读令牌检查公开
构建源；验证过程不读取 Apple Secrets。虚拟证书不是 Apple 开发证书。

- [固定 SideSign 源码](https://github.com/SideStore/SideSign/tree/10b446fc6fc47fe81b60879dfb126d0c8098ec29)
- [Apple 免费账号限制](https://developer.apple.com/help/account/basics/about-your-developer-account)
- [GitHub 模板仓库](https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-repository-from-a-template)
- [GitHub Actions 计费](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
- [GitHub 定时任务](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)
- [SideStore Anisette](https://docs.sidestore.io/docs/advanced/anisette)
- [保持原签名的安装命令](https://github.com/doronz88/pymobiledevice3/blob/master/pymobiledevice3/cli/apps.py)

工具下载固定版本并验证 SHA-256。Swift 便携库来自 Apple Authenticode 验证通过的
官方安装包，来源、哈希和 Swift／ICU 许可包含在运行库 ZIP 中。
SideSign 使用 GPL-3.0，工具与应用代码分开运行。

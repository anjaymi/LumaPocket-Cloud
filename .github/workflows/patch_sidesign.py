"""Narrow V3 protocol/header corrections against reviewed SideSign 752d1ef.

Protocol reference: SideStore/apple-private-apis omnisette/remote_anisette_v3.rs.
Request headers/session reference: SideStore/SideSign PR 8 and SideInstaller's
vendored isideload GrandSlam client. No certificate checks are disabled.
"""
import hashlib
from pathlib import Path
import sys

root = Path(sys.argv[1])


def change(path, replacements):
    file = root / path
    source = file.read_text(encoding='utf-8')
    for before, after, count in replacements:
        if source.count(before) != count:
            raise RuntimeError('Unexpected pinned source at ' + path)
        source = source.replace(before, after)
    file.write_text(source, encoding='utf-8', newline='\n')
    print(path + ': ' + hashlib.sha256(source.encode()).hexdigest())


change('Sources/Anisette/RemoteAnisetteDataProvider.swift', [(
    'let cleanIdentifier = identifier.map { String(format: "%02x", $0) }.joined()',
    'let cleanIdentifier = Data(identifier).base64EncodedString()', 2,
)])

change('Sources/Anisette/AnisetteDataManager.swift', [
    ('import AnisetteKit', 'import AnisetteKit\nimport GSACryptoKit', 1),
    ('        let clientInfo = headers?.clientInfo ?? Constants.Anisette.defaultClientInfo\n'
     '        let client = try await getClient(for: resolvedMode, clientInfo: clientInfo)',
     '''        // V3 local-user identity is SHA256(the same 16-byte identifier sent
        // to the server), not AnisetteKit's shared placeholder value.
        let identifierData = withUnsafeBytes(of: identifier.uuid) { Data($0) }
        guard let localUserHash = CryptoUtilities.sha256(identifierData) else {
            throw AnisetteError.invalidAnisetteData
        }
        var requestHeaders = headers ?? AnisetteRequestHeaders()
        requestHeaders.localUserID = localUserHash.map { String(format: "%02x", $0) }.joined()
        if requestHeaders.deviceID == nil { requestHeaders.deviceID = identifier.uuidString.lowercased() }
        let clientInfo = requestHeaders.clientInfo ?? Constants.Anisette.defaultClientInfo
        let client = try await getClient(for: resolvedMode, clientInfo: clientInfo)''', 1),
    ('                storage: .memory(existingBlob: existingAdiBlob),\n                headers: headers',
     '                storage: .memory(existingBlob: existingAdiBlob),\n                headers: requestHeaders', 1),
])

change('Sources/DeveloperPortal/Authentication.swift', [(
    '''        let headers: [String: String] = [
            "Content-Type": "text/x-xml-plist",
            "X-MMe-Client-Info": anisetteData.clientInfo,
            "Accept": "*/*",
            "User-Agent": h.grandSlam.userAgent,
            "Connection": "close"
        ]''',
    '''        let headers: [String: String] = [
            "Content-Type": "text/x-xml-plist",
            "Accept": "text/x-xml-plist",
            "X-Mme-Client-Info": anisetteData.clientInfo,
            "User-Agent": anisetteData.userAgent,
            "X-Xcode-Version": "14.2 (14C18)",
            "X-Apple-App-Info": h.grandSlam.authApp,
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-M": anisetteData.machineID,
            "X-Apple-I-MD-LU": anisetteData.localUserID,
            "X-Apple-I-MD-RINFO": anisetteData.routingInfo,
            "X-Mme-Device-Id": anisetteData.deviceID,
            "X-Apple-I-SRL-NO": anisetteData.serialNumber,
            "X-Apple-I-Client-Time": anisetteData.clientTime,
            "X-Apple-Locale": anisetteData.locale,
            "X-Apple-I-TimeZone": anisetteData.timeZone,
            "Connection": "close"
        ]''', 1,
)])

change('Sources/DeveloperPortal/DeveloperPortalAPI.swift', [(
    '''    public init(session: URLSession = .shared, customHeaders: SideSignHeaders = SideSignHeaders()) {
        self.session = session''',
    '''    private static func authenticationSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.httpShouldUsePipelining = false
        config.httpMaximumConnectionsPerHost = 1
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.urlCache = nil
        config.timeoutIntervalForRequest = 60
        config.timeoutIntervalForResource = 120
        return URLSession(configuration: config)
    }

    public init(session: URLSession? = nil, customHeaders: SideSignHeaders = SideSignHeaders()) {
        self.session = session ?? Self.authenticationSession()''', 1,
)])

# A network or export failure after Apple accepts the CSR must not discard the
# only private key and leave an un-reusable certificate consuming the free slot.
change('Sources/Models/CertificateRequest.swift', [(
    '    public init(machineName: String) throws {',
    '''    public init(machineName: String, privateKey: Data, csrData: Data) {
        self.machineName = machineName
        self.privateKey = privateKey
        self.csrData = csrData
    }

    public init(machineName: String) throws {''', 1,
)])

change('Sources/DeveloperPortal/Certificates.swift', [
    ('    func addCertificate(machineName: String, type: CertificateType, to team: Team, session: Session) async throws -> KeyStore {',
     '''    func addCertificate(machineName: String, type: CertificateType, to team: Team, session: Session) async throws -> KeyStore {
        return try await addCertificate(machineName: machineName, type: type, to: team,
                                        session: session, recoveryKeyURL: nil)
    }

    func addCertificate(machineName: String, type: CertificateType, to team: Team,
                        session: Session, recoveryKeyURL: URL?) async throws -> KeyStore {''', 1),
    ('            certRequest = try CertificateRequest(machineName: machineName)',
     '''            if let keyURL = recoveryKeyURL {
                let csrURL = keyURL.deletingPathExtension().appendingPathExtension("csr")
                let hasKey = FileManager.default.fileExists(atPath: keyURL.path)
                let hasCSR = FileManager.default.fileExists(atPath: csrURL.path)
                guard hasKey == hasCSR else {
                    throw DeveloperPortalError.invalidCertificateRequest(cause: "Incomplete local certificate recovery files.")
                }
                if hasKey {
                    certRequest = CertificateRequest(machineName: machineName,
                        privateKey: try Data(contentsOf: keyURL), csrData: try Data(contentsOf: csrURL))
                } else {
                    certRequest = try CertificateRequest(machineName: machineName)
                    try certRequest.privateKey.write(to: keyURL, options: .atomic)
                    try certRequest.csrData.write(to: csrURL, options: .atomic)
                    #if !os(Windows)
                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
                    #endif
                }
            } else {
                certRequest = try CertificateRequest(machineName: machineName)
            }''', 1),
])

change('CLI/CommandHandler.swift', [(
    '                let keyStore = try await portal.addCertificate(machineName: machineName, type: resolvedType, to: team, session: session)',
    '''                let recoveryKeyURL = outPath.map {
                    URL(fileURLWithPath: $0).deletingLastPathComponent().appendingPathComponent("certificate-request.key")
                }
                let keyStore = try await portal.addCertificate(machineName: machineName, type: resolvedType,
                    to: team, session: session, recoveryKeyURL: recoveryKeyURL)''', 1,
)])

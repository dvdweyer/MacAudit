// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "AuditKit",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "AuditKit", targets: ["AuditKit"]),
        .executable(name: "macaudit", targets: ["macaudit"]),
    ],
    targets: [
        .target(
            name: "AuditKit",
            linkerSettings: [
                .linkedLibrary("sqlite3"),
                .linkedFramework("IOKit"),
                .linkedFramework("Security"),
                .linkedFramework("SystemConfiguration"),
                .linkedFramework("OpenDirectory"),
                .linkedFramework("ServiceManagement"),
            ]
        ),
        .executableTarget(name: "macaudit", dependencies: ["AuditKit"]),
        .testTarget(name: "AuditKitTests", dependencies: ["AuditKit"]),
    ]
)

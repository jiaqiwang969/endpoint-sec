// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "ESGuardMenuBar",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "ESGuardMenuBar", targets: ["ESGuardMenuBar"])
    ],
    dependencies: [],
    targets: [
        .executableTarget(
            name: "ESGuardMenuBar",
            dependencies: [],
            path: "Sources/ESGuardMenuBar"
        )
    ]
)

// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "AgentSmithMenuBar",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "AgentSmithMenuBar", targets: ["AgentSmithMenuBar"])
    ],
    dependencies: [],
    targets: [
        .executableTarget(
            name: "AgentSmithMenuBar",
            dependencies: [],
            path: "Sources/AgentSmithMenuBar"
        ),
        .testTarget(
            name: "AgentSmithMenuBarTests",
            dependencies: ["AgentSmithMenuBar"],
            path: "Tests/AgentSmithMenuBarTests"
        )
    ]
)

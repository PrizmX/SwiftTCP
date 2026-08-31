// swift-tools-version: 6.3

import PackageDescription

let package = Package(
    name: "SwiftTCP",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
        .tvOS(.v17),
    ],
    products: [
        .library(name: "SwiftTCP", targets: ["SwiftTCP"]),
        .executable(name: "SwiftTCPBench", targets: ["SwiftTCPBench"]),
    ],
    targets: [
        .target(name: "SwiftTCP"),
        .executableTarget(
            name: "SwiftTCPBench",
            dependencies: ["SwiftTCP"]
        ),
        .testTarget(
            name: "SwiftTCPTests",
            dependencies: ["SwiftTCP"]
        ),
    ],
    swiftLanguageModes: [.v6]
)

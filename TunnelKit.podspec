Pod::Spec.new do |s|
    s.name              = "TunnelKit"
    s.version           = "2.0.0"
    s.summary           = "Non-official OpenVPN client for Apple platforms."

    s.homepage          = "https://github.com/passepartoutvpn/tunnelkit"
    s.license           = { :type => "GPLv3", :file => "LICENSE" }
    s.author            = { "Davide De Rosa" => "keeshux@gmail.com" }
    s.source            = { :git => "https://github.com/passepartoutvpn/tunnelkit.git", :tag => "v#{s.version}" }
    s.swift_version     = "5.0"

    s.ios.deployment_target = "11.0"
    s.osx.deployment_target = "10.11"

    s.default_subspecs = "Core", "OpenVPN", "AppExtension"

    s.subspec "Core" do |p|
        p.source_files          = "TunnelKit/Sources/Core/**/*.{h,m,swift}"
        p.private_header_files  = "TunnelKit/Sources/Core/**/*.h"
        p.preserve_paths        = "TunnelKit/Sources/Core/*.modulemap"
        p.pod_target_xcconfig   = { "SWIFT_INCLUDE_PATHS" => "${PODS_TARGET_SRCROOT}/TunnelKit/Sources/Core",
                                    "APPLICATION_EXTENSION_API_ONLY" => "YES" }
        p.dependency "SwiftyBeaver"
        p.dependency "OpenSSL-Apple", "~> 1.1.0j.2"
        p.libraries = "resolv"
    end

    s.subspec "OpenVPN" do |p|
        p.source_files          = "TunnelKit/Sources/OpenVPN/**/*.{h,m,swift}"
        p.private_header_files  = "TunnelKit/Sources/OpenVPN/**/*.h"
        p.preserve_paths        = "TunnelKit/Sources/OpenVPN/*.modulemap"
        p.pod_target_xcconfig   = { "OTHER_LDFLAGS" => "-framework openssl",
                                    "SWIFT_INCLUDE_PATHS" => "${PODS_TARGET_SRCROOT}/TunnelKit/Sources/OpenVPN",
                                    "APPLICATION_EXTENSION_API_ONLY" => "YES" }

        p.dependency "TunnelKit/Core"
    end

    s.subspec "AppExtension" do |p|
        p.source_files          = "TunnelKit/Sources/AppExtension/**/*.swift"
        p.frameworks            = "NetworkExtension"
        p.pod_target_xcconfig   = { "APPLICATION_EXTENSION_API_ONLY" => "YES" }

        p.dependency "TunnelKit/OpenVPN"
    end

    s.subspec "LZO" do |p|
        p.source_files          = "TunnelKit/Sources/Core/LZO.h",
                                  "TunnelKit/Sources/Core/Errors.{h,m}",
                                  "TunnelKit/Sources/LZO/lib/*lzo*.{h,m,c}"
        p.private_header_files  = "TunnelKit/Sources/Core/LZO.h",
                                  "TunnelKit/Sources/Core/Errors.h",
                                  "TunnelKit/Sources/LZO/lib/*lzo*.h"
        p.pod_target_xcconfig   = { "APPLICATION_EXTENSION_API_ONLY" => "YES" }
    end
end

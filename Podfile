source 'https://github.com/CocoaPods/Specs.git'
use_frameworks!

def shared_pods
    pod 'SwiftyBeaver'
    pod 'OpenSSL-Apple', '~> 1.1.1h.10'
end

def demo_pods
    pod 'SwiftyBeaver'
end

abstract_target 'ios' do
    platform :ios, '12.0'
    target 'TunnelKit-iOS' do
        shared_pods
    end
    target 'TunnelKitDemo-iOS' do
        demo_pods
    end
    target 'TunnelKitDemoTunnel-iOS' do
    end
end

abstract_target 'macos' do
    platform :osx, '10.15'
    target 'TunnelKit-macOS' do
        shared_pods
    end
    target 'TunnelKitDemo-macOS' do
        demo_pods
    end
    target 'TunnelKitDemoTunnel-macOS' do
    end
end

target 'TunnelKitTests-iOS' do
    platform :ios, '12.0'
end
target 'TunnelKitHost' do
    platform :ios, '12.0'
end
target 'TunnelKitTests-macOS' do
    platform :osx, '10.15'
end

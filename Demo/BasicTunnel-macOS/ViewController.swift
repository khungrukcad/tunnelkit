//
//  ViewController.swift
//  BasicTunnel-macOS
//
//  Created by Davide De Rosa on 10/15/17.
//  Copyright (c) 2018 Davide De Rosa. All rights reserved.
//
//  https://github.com/keeshux
//
//  This file is part of TunnelKit.
//
//  TunnelKit is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  TunnelKit is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with TunnelKit.  If not, see <http://www.gnu.org/licenses/>.
//
//  This file incorporates work covered by the following copyright and
//  permission notice:
//
//      Copyright (c) 2018-Present Private Internet Access
//
//      Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
//      The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
//      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
//

import Cocoa
import NetworkExtension
import TunnelKit

private let appGroup = "DTDYD63ZX9.group.com.algoritmico.macos.demo.BasicTunnel"

private let tunnelIdentifier = "com.algoritmico.macos.demo.BasicTunnel.Extension"

class ViewController: NSViewController {
    @IBOutlet var textUsername: NSTextField!
    
    @IBOutlet var textPassword: NSTextField!
    
    @IBOutlet var textServer: NSTextField!
    
    @IBOutlet var textDomain: NSTextField!
    
    @IBOutlet var textPort: NSTextField!
    
    @IBOutlet var buttonConnection: NSButton!
    
    //
    
    let vpn = StandardVPNProvider(bundleIdentifier: tunnelIdentifier)

    override func viewDidLoad() {
        super.viewDidLoad()
        
        textServer.stringValue = "es"
        textDomain.stringValue = "lazerpenguin.com"
        textPort.stringValue = "443"
        textUsername.stringValue = ""
        textPassword.stringValue = ""
        
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(VPNStatusDidChange(notification:)),
            name: .NEVPNStatusDidChange,
            object: nil
        )
        
        vpn.prepare(completionHandler: nil)
        
        //
        
        testFetchRef()
    }
    
    @IBAction func connectionClicked(_ sender: Any) {
        switch vpn.status {
        case .disconnected:
            connect()
            
        case .connected, .connecting, .disconnecting:
            disconnect()
        }
    }
    
    func connect() {
        let server = textServer.stringValue
        let domain = textDomain.stringValue
        let hostname = ((domain == "") ? server : [server, domain].joined(separator: "."))
        let port = UInt16(textPort.stringValue)!

        let credentials = OpenVPN.Credentials(textUsername.stringValue, textPassword.stringValue)
        let cfg = Configuration.make(hostname: hostname, port: port, socketType: .udp)
        let proto = try! cfg.generatedTunnelProtocol(
            withBundleIdentifier: tunnelIdentifier,
            appGroup: appGroup,
            credentials: credentials
        )
        let neCfg = NetworkExtensionVPNConfiguration(protocolConfiguration: proto, onDemandRules: [])
        vpn.reconnect(configuration: neCfg) { (error) in
            if let error = error {
                print("configure error: \(error)")
                return
            }
        }
    }
    
    func disconnect() {
        vpn.disconnect(completionHandler: nil)
    }

    func updateButton() {
        switch vpn.status {
        case .connected, .connecting:
            buttonConnection.title = "Disconnect"
            
        case .disconnected:
            buttonConnection.title = "Connect"
            
        case .disconnecting:
            buttonConnection.title = "Disconnecting"
        }
    }
    
    @objc private func VPNStatusDidChange(notification: NSNotification) {
        print("VPNStatusDidChange: \(vpn.status)")
        updateButton()
    }

    private func testFetchRef() {
//        let keychain = Keychain(group: ViewController.APP_GROUP)
//        let username = "foo"
//        let password = "bar"
//
//        guard let _ = try? keychain.set(password: password, for: username) else {
//            print("Couldn't set password")
//            return
//        }
//        guard let passwordReference = try? keychain.passwordReference(for: username) else {
//            print("Couldn't get password reference")
//            return
//        }
//        guard let fetchedPassword = try? Keychain.password(for: username, reference: passwordReference) else {
//            print("Couldn't fetch password")
//            return
//        }
//
//        print("\(username) -> \(password)")
//        print("\(username) -> \(fetchedPassword)")
    }
}


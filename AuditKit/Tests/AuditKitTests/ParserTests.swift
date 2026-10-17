import Testing
import Foundation
@testable import AuditKit

@Suite struct ParserTests {
    @Test func netstatListeners() {
        let output = """
        Active Internet connections (including servers)
        Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
        tcp4       0      0  192.168.1.58.50523     34.149.66.165.443      ESTABLISHED         8820        14039  131072  131600           claude:11315  00102 00000008 00000000001cc572 20000081 04000900      3      0 000004
        tcp4       0      0  *.5000                 *.*                    LISTEN                 0            0  131072  131072    ControlCenter:696    00100 00000006 0000000000120773 00000001 00000800      1      0 000000
        tcp4       0      0  127.0.0.1.631          *.*                    LISTEN                 0            0  131072  131072  Google Chrome H:812    00100 00000006 0000000000120773 00000001 00000800      1      0 000000
        tcp6       0      0  ::1.8080               *.*                    LISTEN                 0            0  131072  131072           node:900    00100 00000006 0000000000120773 00000001 00000800      1      0 000000
        """
        let sockets = Parsers.netstat(output)
        #expect(sockets.count == 4)
        let listeners = sockets.filter(\.isListening)
        #expect(listeners.count == 3)
        #expect(listeners[0].process == "ControlCenter")
        #expect(listeners[0].pid == 696)
        #expect(listeners[0].port == 5000)
        #expect(!listeners[0].isLoopback)
        #expect(listeners[1].process == "Google Chrome H")
        #expect(listeners[1].isLoopback)
        #expect(listeners[2].isLoopback)
        #expect(listeners[2].port == 8080)
    }

    @Test func netstatUDP() {
        let output = """
        udp4       0      0  *.320                  *.*                                     6163948            0  786896    9216      kernel_task:0      00180 00000000 00000000001c5f4c 20000000 00100800      2      0 000002
        udp4       0      0  192.168.1.58.60867     17.250.85.11.443                           7734         1584  786896    9216           cloudd:667    00102 00020000 00000000001cc5c1 30100001 04280900      2      0 000002
        """
        let sockets = Parsers.netstat(output)
        #expect(sockets.count == 2)
        #expect(sockets[0].isListening)
        #expect(sockets[0].process == "kernel_task")
        #expect(!sockets[1].isListening)
    }

    @Test func firewallApps() {
        let output = """
        Total number of apps = 2
        1 : /usr/libexec/remoted
                     (Allow incoming connections)
        2 : /Applications/Some App.app
                     (Block incoming connections)
        """
        #expect(Parsers.firewallApps(output) == [
            .init(path: "/usr/libexec/remoted", allowed: true),
            .init(path: "/Applications/Some App.app", allowed: false),
        ])
        #expect(Parsers.firewallState("Firewall is disabled. (State = 0)") == 0)
        #expect(Parsers.firewallState("Firewall is enabled. (State = 1)") == 1)
    }

    @Test func sipAndScreenLock() {
        #expect(Parsers.sipEnabled("System Integrity Protection status: enabled."))
        #expect(!Parsers.sipEnabled("System Integrity Protection status: enabled (Custom Configuration).\n\nConfiguration:"))
        #expect(!Parsers.sipEnabled("System Integrity Protection status: disabled."))
        #expect(Parsers.screenLockDelay("2026-10-17 sysadminctl[1:2] screenLock delay is immediate") == "immediate")
        #expect(Parsers.screenLockDelay("screenLock delay is 300 seconds") == "300 seconds")
        #expect(Parsers.screenLockDelay("screenLock is off") == "off")
    }

    @Test func launchdOverrides() {
        let output = """
        \tdisabled services = {
        \t\t"com.apple.ftpd" => disabled
        \t\t"com.openssh.sshd" => enabled
        \t\t"com.example.legacy" => true
        \t}
        """
        let map = Parsers.launchdOverrides(output)
        #expect(map["com.apple.ftpd"] == true)
        #expect(map["com.openssh.sshd"] == false)
        #expect(map["com.example.legacy"] == true)
    }

    @Test func sharePoints() {
        let output = """

        \t\t\tList of Share Points
        name:\t\tAlice's Public Folder
        path:\t\t/Users/alice/Public
        \tsmb:\t{
            \t\tname:\tAlice's Public Folder
            \t\tshared:\t1
            \t\tguest access:\t1
            \t\tread-only:\t0
            \t\tsealed:\t0
        \t}

        name:\t\tProjects
        path:\t\t/Volumes/Data/Projects
        \tsmb:\t{
            \t\tname:\tProjects
            \t\tshared:\t1
            \t\tguest access:\t0
            \t\tread-only:\t1
        \t}
        """
        let shares = Parsers.sharePoints(output)
        #expect(shares.count == 2)
        #expect(shares[0] == .init(name: "Alice's Public Folder", path: "/Users/alice/Public", shared: true, guestAccess: true, readOnly: false))
        #expect(shares[1] == .init(name: "Projects", path: "/Volumes/Data/Projects", shared: true, guestAccess: false, readOnly: true))
    }

    @Test func systemExtensions() {
        let output = """
        4 extension(s)
        --- com.apple.system_extension.network_extension (Go to 'System Settings > General > Login Items & Extensions > Network Extensions' to modify these system extension(s))
        enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
        *\t*\tW5364U7YZB\tio.tailscale.ipn.macsys.network-extension (1.104.1/101.104.1)\tTailscale Network Extension\t[activated enabled]
        --- com.apple.system_extension.endpoint_security (Go to 'System Settings')
        enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
        \t\tW5W395V82Y\tcom.example.Shield (10.12.0/377)\tExample protection\t[terminated waiting to uninstall on reboot]
        """
        let exts = Parsers.systemExtensions(output)
        #expect(exts.count == 2)
        #expect(exts[0].category == "com.apple.system_extension.network_extension")
        #expect(exts[0].enabled && exts[0].active)
        #expect(exts[0].bundleID == "io.tailscale.ipn.macsys.network-extension")
        #expect(exts[0].version == "1.104.1/101.104.1")
        #expect(exts[0].name == "Tailscale Network Extension")
        #expect(!exts[1].enabled && !exts[1].active)
        #expect(exts[1].state == "terminated waiting to uninstall on reboot")
    }

    @Test func pluginkit() {
        let output = """
             com.example.thumbnail(3.8)
        \t            Path = /Applications/Example.app/Contents/PlugIns/Thumb.appex
        \t             SDK = com.apple.quicklook.thumbnail
        \t    Display Name = Thumbnails
        \t     Parent Name = Example
        +    com.example.finder(1.0)
        \t            Path = /Applications/Example.app/Contents/PlugIns/Finder.appex
        \t             SDK = com.apple.FinderSync
        """
        let entries = Parsers.pluginkit(output)
        #expect(entries.count == 2)
        #expect(entries[0].identifier == "com.example.thumbnail")
        #expect(entries[0].version == "3.8")
        #expect(entries[0].election == nil)
        #expect(entries[0].displayName == "Thumbnails")
        #expect(entries[1].election == "+")
        #expect(entries[1].sdk == "com.apple.FinderSync")
    }

    @Test func networkConnections() {
        let output = """
        Available network connection services in the current set (*=enabled):
        * (Connected)      5FBD9CDB-1137-4B79-A446-7C640464FDAD VPN (io.tailscale.ipn.macsys) "Tailscale"                      [VPN:io.tailscale.ipn.macsys]
          (Disconnected)   0A1B2C3D-1137-4B79-A446-7C640464FDAD PPP --> L2TP          "Office"                         [PPP/L2TP]
        """
        let vpns = Parsers.networkConnections(output)
        #expect(vpns.count == 2)
        #expect(vpns[0].name == "Tailscale")
        #expect(vpns[0].status == "Connected")
        #expect(vpns[0].enabled)
        #expect(!vpns[1].enabled)
    }

    @Test func hostsAndSudoAndPAM() {
        let hosts = """
        ##
        127.0.0.1\tlocalhost
        255.255.255.255\tbroadcasthost
        ::1             localhost
        0.0.0.0 tracker.example.com # blocked
        """
        #expect(Parsers.customHostEntries(hosts) == ["0.0.0.0 tracker.example.com"])

        let sudoers = """
        Defaults env_reset
        root ALL = (ALL) ALL
        %admin  ALL = (ALL) ALL
        alice ALL=(ALL) NOPASSWD: /usr/bin/pmset
        """
        #expect(Parsers.sudoRules(sudoers) == ["alice ALL=(ALL) NOPASSWD: /usr/bin/pmset"])

        let pam = """
        # sudo: auth account password session
        auth       sufficient     pam_tid.so
        auth       sufficient     pam_smartcard.so
        auth       required       pam_opendirectory.so
        auth       optional       /usr/local/lib/pam/pam_evil.so
        """
        #expect(Parsers.nonStandardPAMModules(pam) == ["pam_tid.so", "/usr/local/lib/pam/pam_evil.so"])
    }

    @Test func falsePositivesFromRealRun() {
        #expect(Parsers.cupsSharePrinters("_remote_admin=0\n_share_printers=0\nBrowseLocalProtocols=dnssd") == false)
        #expect(Parsers.cupsSharePrinters("_share_printers=1\n"))

        let pam = """
        auth       include        sudo_local
        auth       sufficient     pam_smartcard.so
        """
        #expect(Parsers.nonStandardPAMModules(pam).isEmpty)

        let sudoers = """
        Cmnd_Alias PMSET= /usr/bin/pmset -a disablesleep 1
        %admin ALL=(ALL) NOPASSWD: PMSET
        """
        #expect(Parsers.sudoRules(sudoers) == ["%admin ALL=(ALL) NOPASSWD: PMSET"])
    }

    @Test func profiles() {
        let enrollment = Parsers.enrollmentStatus("Enrolled via DEP: No\nMDM enrollment: Yes (User Approved)\nMDM server: https://mdm.example.com/checkin")
        #expect(enrollment["MDM enrollment"] == "Yes (User Approved)")
        #expect(enrollment["MDM server"] == "https://mdm.example.com/checkin")

        let output = """
        There are 1 configuration profiles installed

        _computerlevel[1] attribute: name: Corporate WiFi
        _computerlevel[1] attribute: profileIdentifier: com.example.wifi
        _computerlevel[1] attribute: profileDisplayName: Corporate WiFi
        _computerlevel[1] attribute: profileOrganization: Example Corp
        _computerlevel[1] payload[1] type = com.apple.wifi.managed
        """
        let profiles = Parsers.configurationProfiles(output)
        #expect(profiles.count == 1)
        #expect(profiles[0].attributes["profileIdentifier"] == "com.example.wifi")
        #expect(profiles[0].payloadTypes == ["com.apple.wifi.managed"])
    }

    @Test func timeMachine() {
        let output = """
        ====================================================
        Name          : Backup Disk
        Kind          : Local
        Mount Point   : /Volumes/Backup Disk
        ID            : 1234-ABCD
        """
        let dests = Parsers.tmutilDestinations(output)
        #expect(dests.count == 1)
        #expect(dests[0]["Name"] == "Backup Disk")
        #expect(dests[0]["ID"] == "1234-ABCD")
        #expect(Parsers.tmutilDestinations("tmutil: No destinations configured.").isEmpty)
        #expect(Parsers.backupDate("/Volumes/B/2026-10-01-120000.backup") != nil)
    }

    @Test func btmDump() {
        let output = """
        ========================
         Records for UID 501 : 1234
        ========================
         Items:
         #1:
                         UUID: 1111
                         Name: Example Helper
                    Developer Name: Example Inc
                         Type: legacy daemon (0x10010)
                  Disposition: [enabled, allowed, visible, notified] (0xb)
                   Identifier: 16.com.example.helper
         #2:
                         Name: Other
                   Identifier: 2.com.example.other
        """
        let items = Parsers.btmDump(output)
        #expect(items.count == 2)
        #expect(items[0]["Name"] == "Example Helper")
        #expect(items[0]["Disposition"] == "[enabled, allowed, visible, notified] (0xb)")
        #expect(items[1]["Identifier"] == "2.com.example.other")
    }
}

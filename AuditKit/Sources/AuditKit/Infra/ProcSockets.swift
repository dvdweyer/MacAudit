import Foundation
import Darwin

/// Enumerates listening/bound sockets per process via libproc. Without root, only processes owned
/// by the current user can be inspected.
enum ProcSockets {
    struct Result {
        var sockets: [Parsers.Socket]
        var inaccessibleProcesses: Int
    }

    static func listeningSockets() -> Result {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return Result(sockets: [], inaccessibleProcesses: 0) }
        var pids = [pid_t](repeating: 0, count: Int(count) * 2)
        let filled = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
        var sockets: [Parsers.Socket] = []
        var inaccessible = 0

        for pid in pids.prefix(Int(max(filled, 0))) where pid > 0 {
            let size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
            guard size > 0 else { inaccessible += 1; continue }
            var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(size) / MemoryLayout<proc_fdinfo>.stride)
            let used = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, size)
            guard used > 0 else { inaccessible += 1; continue }
            let name = processName(pid)

            for fd in fds.prefix(Int(used) / MemoryLayout<proc_fdinfo>.stride) where fd.proc_fdtype == PROX_FDTYPE_SOCKET {
                var info = socket_fdinfo()
                let infoSize = Int32(MemoryLayout<socket_fdinfo>.size)
                guard proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &info, infoSize) == infoSize else { continue }
                if let socket = socket(from: info.psi, process: name, pid: pid) {
                    sockets.append(socket)
                }
            }
        }
        return Result(sockets: sockets, inaccessibleProcesses: inaccessible)
    }

    private static func socket(from si: socket_info, process: String, pid: pid_t) -> Parsers.Socket? {
        let inInfo: in_sockinfo
        let isTCP: Bool
        switch Int(si.soi_kind) {
        case SOCKINFO_TCP:
            guard si.soi_proto.pri_tcp.tcpsi_state == TSI_S_LISTEN else { return nil }
            inInfo = si.soi_proto.pri_tcp.tcpsi_ini
            isTCP = true
        case SOCKINFO_IN where si.soi_protocol == IPPROTO_UDP:
            inInfo = si.soi_proto.pri_in
            guard inInfo.insi_fport == 0 else { return nil }
            isTCP = false
        default:
            return nil
        }
        let isV6 = inInfo.insi_vflag & UInt8(INI_IPV6) != 0
        let port = Int(UInt16(bigEndian: UInt16(truncatingIfNeeded: inInfo.insi_lport)))
        let host = address(inInfo, v6: isV6)
        return Parsers.Socket(proto: (isTCP ? "tcp" : "udp") + (isV6 ? "6" : "4"),
                              localAddress: "\(host).\(port)", foreignAddress: "*.*",
                              state: isTCP ? "LISTEN" : "", process: process, pid: pid)
    }

    private static func address(_ info: in_sockinfo, v6: Bool) -> String {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        if v6 {
            var addr = info.insi_laddr.ina_6
            if withUnsafeBytes(of: &addr, { $0.allSatisfy { $0 == 0 } }) { return "*" }
            inet_ntop(AF_INET6, &addr, &buffer, socklen_t(buffer.count))
        } else {
            var addr = info.insi_laddr.ina_46.i46a_addr4
            if addr.s_addr == 0 { return "*" }
            inet_ntop(AF_INET, &addr, &buffer, socklen_t(buffer.count))
        }
        return String(cBuffer: buffer)
    }

    private static func processName(_ pid: pid_t) -> String {
        var buffer = [CChar](repeating: 0, count: 256)
        proc_name(pid, &buffer, UInt32(buffer.count))
        let name = String(cBuffer: buffer)
        return name.isEmpty ? "pid \(pid)" : name
    }
}

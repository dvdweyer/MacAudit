import Foundation
import OpenDirectory

public struct DirectoryRecord: Sendable {
    public var name: String
    public var attributes: [String: [String]]

    public func first(_ key: String) -> String? { attributes[key]?.first }
}

/// Read-only queries against the local directory node.
public enum DirectoryService {
    public static func records(type: String, attributes: [String]? = nil) throws -> [DirectoryRecord] {
        let node = try ODNode(session: ODSession.default(), type: ODNodeType(kODNodeTypeLocalNodes))
        let query = try ODQuery(node: node, forRecordTypes: type, attribute: nil,
                                matchType: ODMatchType(kODMatchAny), queryValues: nil,
                                returnAttributes: attributes ?? kODAttributeTypeAllAttributes, maximumResults: 0)
        let results = try query.resultsAllowingPartial(false) as? [ODRecord] ?? []
        return results.map { record in
            var attrs: [String: [String]] = [:]
            let values = (try? record.recordDetails(forAttributes: attributes)) as? [String: Any] ?? [:]
            for (key, value) in values {
                if let strings = value as? [String] {
                    attrs[key] = strings
                } else if let any = value as? [Any] {
                    attrs[key] = any.compactMap { $0 as? String }
                }
            }
            return DirectoryRecord(name: record.recordName, attributes: attrs)
        }
    }

    public static func groupMembers(_ group: String) -> [String] {
        let groups = (try? records(type: kODRecordTypeGroups, attributes: [kODAttributeTypeGroupMembership])) ?? []
        return groups.first { $0.name == group }?.attributes[kODAttributeTypeGroupMembership] ?? []
    }
}

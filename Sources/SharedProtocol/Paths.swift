import Foundation

public enum InstalledPaths {
    public static let applicationRoot = "/Library/Application Support/ServerPCSSHControl"
    public static let applicationBundle = "/Applications/Mac SSH Manager.app"
    public static let stateRoot = applicationRoot + "/State"
    public static let leaseFile = stateRoot + "/lease.json"
    public static let settingsFile = stateRoot + "/settings.json"
    public static let clientPolicyFile = stateRoot + "/trusted-client.json"
    public static let auditFile = "/var/log/serverpc-ssh-control.jsonl"
    public static let pfAnchorFile = "/etc/pf.anchors/com.serverpc.ssh-control"

    public static let pfAnchorName = "com.serverpc.ssh-control"
    public static let controllerMachService = "com.serverpc.ssh-control.controller"
    public static let controllerBundleIdentifier = "com.serverpc.ssh-control.controller"
    public static let enforcerBundleIdentifier = "com.serverpc.ssh-control.enforcer"
    public static let menuBundleIdentifier = "com.serverpc.ssh-control.menu"
    public static let authorizationRight = "com.serverpc.ssh-control.open"
}

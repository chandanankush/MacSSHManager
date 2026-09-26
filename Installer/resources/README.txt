MAC SSH MANAGER

What this app does
This app controls normal SSH access on this Mac (port 22). SSH starts CLOSED.
Use the menu-bar app to open SSH for a short time when you need it. You will
be asked for an administrator password before SSH can be opened.

The installer enables macOS Remote Login if it was off and creates missing SSH
host keys. Existing SSH host keys are never replaced. Root login is disabled;
sign in with a normal or dedicated non-root SSH account.

Where to find the app
/Applications/Mac SSH Manager.app

Basic use
1. Open Mac SSH Manager from Applications.
2. Choose an access time.
3. Click Open SSH and approve the administrator prompt.
4. Click Close now when you are finished. SSH also closes automatically when
   the selected time ends.

Viewing recent activity
Click View full history in the menu. A searchable window shows access changes
and successful SSH connections and disconnections from the last 30 days. It
shows the SSH username and source IP address, but never passwords, SSH keys,
commands, or terminal contents. Viewing history does not ask for a password.

Important
This app only controls normal SSH on port 22. It does not add, remove, or
change SSH keys.

To remove Mac SSH Manager
Only remove it while physically at this Mac. Removing the app also removes its
SSH protection and can make normal SSH reachable again.

Run this command in Terminal and enter an administrator password when asked:

sudo "/Applications/Mac SSH Manager.app/Contents/Resources/uninstall"

The uninstaller closes SSH first, then removes the app and its package-owned
settings. If this installer turned on Remote Login, it turns it off again.

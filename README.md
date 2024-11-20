SteamArchiver
===============

Steam depot downloader utilizing the SteamKit2 library. Supports .NET 8.0

This program must be run from a console, it has no GUI.

## Installation

### Directly from GitHub

Release files do not exist yet
~~Download a binary from [the releases page](https://github.com/SteamRE/SteamArchiver/releases/latest).~~

## Usage

### Downloading one or all depots for an app
```powershell
./SteamArchiver -app <id> [<depotid> [<manifestid>]]
                 [-username <username> [-password <password>]] [other options]
```

For example: `./SteamArchiver -app 730 731 7617088375292372759`

By default it will use anonymous account ([view which apps are available on it here](https://steamdb.info/sub/17906/)).

To use your account, specify the `-username <username>` parameter. Password will be asked interactively if you do
not use specify the `-password` parameter.

### Downloading a workshop item using pubfile id
```powershell
./SteamArchiver -app <id> -pubfile <id> [-username <username> [-password <password>]]
```

For example: `./SteamArchiver -app 730 -pubfile 1885082371`

### Downloading a workshop item using ugc id
```powershell
./SteamArchiver -app <id> -ugc <id> [-username <username> [-password <password>]]
```

For example: `./SteamArchiver -app 730 -ugc 770604181014286929`

## Parameters

Parameter               | Description
----------------------- | -----------
`-app <#> <#> <#>`				| the AppID to download, and optionally the DepotID and ManifestID.
`-ugc <#>`				| the UGC ID to download.
`-beta <branchname>`	| download from specified branch if available (default: Public).
`-betapassword <pass>`	| branch password if applicable.
`-pubfile <#>`			| the PublishedFileId to download. (Will automatically resolve to UGC id)
`-username <user>`		| the username of the account to login to for restricted content.
`-password <pass>`		| the password of the account to login to for restricted content.
`-remember-password`	| if set, remember the password for subsequent logins of this user. (Use `-username <username> -remember-password` as login credentials)
`-validate`				| Include checksum verification of files already downloaded
`-manifest-only`		| downloads a human readable manifest for any depots that would be downloaded.
`-cellid <#>`			| the overridden CellID of the content server to download from.
`-max-servers <#>`		| maximum number of content servers to use. (default: 20).
`-max-downloads <#>`	| maximum number of chunks to download concurrently. (default: 8).
`-loginid <#>`			| a unique 32-bit integer Steam LogonID in decimal, required if running multiple instances of SteamArchiver concurrently.
`-V` or `--version`     | print version and runtime

## Frequently Asked Questions

### Why am I prompted to enter a 2-factor code every time I run the app?
Your 2-factor code authenticates a Steam session. You need to "remember" your session with `-remember-password` which persists the login key for your Steam session.

### Can I run SteamArchiver while an account is already connected to Steam?
Any connection to Steam will be closed if they share a LoginID. You can specify a different LoginID with `-loginid`.

### Why doesn't my password containing special characters work? Do I have to specify the password on the command line?
If you pass the `-password` parameter with a password that contains special characters, you will need to escape the command appropriately for the shell you are using. You do not have to include the `-password` parameter on the command line as long as you include a `-username`. You will be prompted to enter your password interactively.

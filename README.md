# Openvas-Script-Modifier
Openvas-Script-Modifier is a java project that modifies openvas scripts to make them give fixed and detected versions.
[See the corresponding greenbone community topic for more details.](https://community.greenbone.net/t/nasl-scripts-that-do-not-give-version-information/3795)
## Run
- Set `nvtDirectoryPath` variable in `MainNvtSecurityMessageModifier.java` to the path of the directory including all vulnerability test scripts.
- Set `nvtOidListPath` variable in `MainNvtSecurityMessageModifier.java` to the path of desired output directory.
- Run `MainNvtSecurityMessageModifier.java`
## Data
- `nvt_oid_list.txt` includes oid list of the scripts that use version check functions but do not print any version information.
- `OpenvasModifiedScripts`includes modified scripts.
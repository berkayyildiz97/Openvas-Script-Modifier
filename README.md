# Openvas-Script-Modifier
Openvas-Script-Modifier is a java project that modifies openvas scripts to make them give port information, fixed and detected versions.

[See the corresponding greenbone community topic for more details.](https://community.greenbone.net/t/nasl-scripts-that-do-not-give-version-information/3795)
## Modifier for Version Information
### Run
- Set `nvtDirectoryPath` variable in `MainNvtSecurityMessageModifier.java` to the path of the directory including all vulnerability test scripts.
- Set `outputDirectoryPath` variable in `MainNvtSecurityMessageModifier.java` to the path of desired output directory.
- Run `MainNvtSecurityMessageModifier.java`
### Data
- `nvt_oid_list.txt` includes oid list of the scripts that use version check functions but do not print any version information.
- `OpenvasModifiedScripts`includes modified scripts.
## Modifier for Port Information
### Run
- Set `nvtDirectoryPath` variable in `MainNvtPortProducer.java` to the path of the directory including all vulnerability test scripts.
- Set `outputDirectoryPath` variable in `MainNvtPortProducer.java` to the path of desired output directory.
- Run `MainNvtPortProducer.java`
### Data
- `port_producible_nvt_oid_list` includes Java ArrayList objects for the scripts that have cpe variable but do not use any port functions. 
- `OpenvasPortProducedScripts` includes modified scripts.

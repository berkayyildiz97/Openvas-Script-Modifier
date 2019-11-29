import java.io.*;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class NvtSecurityMessageModifier {

    private String nvtDirectoryPath = "";

    private String nvtOidListPath = "";

    private String outputDirectoryPath = "";

    private final Pattern patternVersionIsLess = Pattern.compile("if\\(version_is_less\\(version:([^,]*)");

    private final Pattern patternVersionInRange = Pattern.compile("if\\(version_in_range\\(version:([^,]*)");

    private final Pattern patternVersionIsLessEqual = Pattern.compile("if\\(version_is_less_equal\\(version:([^,]*)");

    private final Pattern patternVersionIsEqual = Pattern.compile("if\\(version_is_equal\\(version:([^,]*)");

    private final Pattern patternPortParameter = Pattern.compile("port:([^\\),]*)");

    private final Pattern patternTestVersion = Pattern.compile("test_version:([^\\),]*)");

    private final Pattern patternTestVersion2 = Pattern.compile("test_version2:([^\\),]*)");

    private final Pattern patternPath = Pattern.compile("[^[,'=\")&+(/;]?]*path=.*;");

    private enum VersionFunction {
        VERSION_IS_LESS,
        VERSION_IN_RANGE,
        VERSION_IS_LESS_EQUAL,
        VERSION_IS_EQUAL
    }

    public NvtSecurityMessageModifier(String nvtDirectoryPath, String nvtOidListPath, String outputDirectoryPath) {
        this.nvtDirectoryPath = nvtDirectoryPath;
        this.nvtOidListPath = nvtOidListPath;
        this.outputDirectoryPath = outputDirectoryPath;
    }

    public void modifyNvtSecurityMessages() throws FileNotFoundException {
        NvtProvider nvtProvider = new NvtProvider();
        ArrayList<File> allNvts = nvtProvider.getNVTFiles(nvtDirectoryPath);

        ArrayList<File> nvts = nvtProvider.getNvtsShouldBeModified(allNvts, nvtOidListPath);

        for(File file : nvts) {
            boolean isScannerInVersionCheck = false;
            boolean isSecurityMessageFound = false;
            String nvtVersionVariable = "";
            Scanner input = new Scanner(file);

            String nvtPath = "";
            String nvtFixedVersion = "";
            String nvtVulnerableRangeVersion1 = "";
            String nvtVulnerableRangeVersion2 = "";
            boolean isNotCompletedVersionInRangeFound = false;

            boolean isAnyVersionCheckFunctionFound = false;

            //"{" --> countBracketsAfterVersionFunction++;
            //"}" --> countBracketsAfterVersionFunction--;
            int countBracketsAfterVersionFunction = 0;

            VersionFunction versionFunction = null;

            File outputFile = new File(outputDirectoryPath + "/" + file.getName());
            PrintWriter printWriter = new PrintWriter(outputFile);



            while (input.hasNextLine()) {
                String line = input.nextLine();

                //To correct test_version that is separated by ",". Because standart version separator is "." and comma separated version caused error in parsing.
                //Reference (version_func.inc) :ver_sep = "."; # Set Standard Separator
                //Comma separated test_version occurs only in flash_player_CB-A08-0059.nasl
                if (file.getName().equals("flash_player_CB-A08-0059.nasl") && line.equals("if(version_is_less_equal(version:flashVer, test_version:\"9,0,115,0\")){")) {
                    line = "if(version_is_less_equal(version:flashVer, test_version:\"9.0.115.0\")){";
                }

                String lineWithoutSpaceChars = line.replaceAll("\\s+","");
                String lineWithoutSpaceCharsLowerCase = lineWithoutSpaceChars.toLowerCase();

                if (lineWithoutSpaceCharsLowerCase.contains("path")) {
                    Matcher matcherPath = patternPath.matcher(lineWithoutSpaceCharsLowerCase);
                    if (matcherPath.find() && lineWithoutSpaceCharsLowerCase.matches("[^[,'=\")&+(/;]?]*path=.*;")) {
                        String matchedStr = matcherPath.group();
                        nvtPath = matchedStr.substring(0, matchedStr.indexOf('='));
                        //To make nvtPath have original letter case
                        int pathIndex = line.toLowerCase().indexOf(nvtPath);
                        nvtPath = line.substring(pathIndex, pathIndex + nvtPath.length());
                    }
                }
                if (isScannerInVersionCheck && line.contains("{")) {
                    int index = lineWithoutSpaceCharsLowerCase.indexOf("{");
                    while (index >= 0) {
                        countBracketsAfterVersionFunction++;
                        index = lineWithoutSpaceCharsLowerCase.indexOf("{", index + 1);
                    }
                }
                if (isScannerInVersionCheck && line.contains("}")) {
                    int index = lineWithoutSpaceCharsLowerCase.indexOf("}");
                    while (index >= 0) {
                        countBracketsAfterVersionFunction--;
                        index = lineWithoutSpaceCharsLowerCase.indexOf("}", index + 1);
                        if (countBracketsAfterVersionFunction <= 0) {
                            countBracketsAfterVersionFunction = 0;
                            isScannerInVersionCheck = false;
                            break;
                        }
                    }
                }
                //There are no fixed version patterns that I found in version_is_less_equal and version_is_equal functions. Fixed version is usually independent from checked version.
                //Example: secpod_trendmicro_officescan_dos_vuln.nasl
                //No fixed version should be produced for version_in_range function. Therefore the code producing fixed version for version_in_ramge is removed.
                //Because some of them have fixed versions in solution header that is independent from the checked version range.
                //Example :secpod_adobe_prdts_mem_crptn_vuln_win_jun11.nasl
                if (lineWithoutSpaceCharsLowerCase.contains("version_is_less(") || lineWithoutSpaceCharsLowerCase.contains("version_in_range(")
                || lineWithoutSpaceCharsLowerCase.contains("version_is_equal(") || lineWithoutSpaceCharsLowerCase.contains("version_is_less_equal(")) {
                    int index = lineWithoutSpaceCharsLowerCase.indexOf("{", lineWithoutSpaceCharsLowerCase.indexOf("version_i"));
                    countBracketsAfterVersionFunction = 0;
                    while (index >= 0) {
                        countBracketsAfterVersionFunction++;
                        index = lineWithoutSpaceCharsLowerCase.indexOf("{", index + 1);
                    }

                    isAnyVersionCheckFunctionFound = true;
                    isScannerInVersionCheck = true;
                    nvtFixedVersion = "";
                    nvtVulnerableRangeVersion1 = "";
                    nvtVulnerableRangeVersion2 = "";
                    versionFunction = null;
                    Matcher matcherVersion = patternVersionIsLess.matcher(lineWithoutSpaceChars);
                    //For version_is_less, fixed Version = test_version
                    if (matcherVersion.find())
                    {
                        versionFunction = VersionFunction.VERSION_IS_LESS;
                        nvtVersionVariable = matcherVersion.group(1);
                        nvtFixedVersion = getTestVersionParameter(patternTestVersion, lineWithoutSpaceChars);
                    }
                    //For version_in_range, vulnerable_range = "test_version - test_version2"
                    matcherVersion = patternVersionInRange.matcher(lineWithoutSpaceChars);
                    if (matcherVersion.find())
                    {
                        versionFunction = VersionFunction.VERSION_IN_RANGE;
                        nvtVersionVariable = matcherVersion.group(1);
                        if (lineWithoutSpaceCharsLowerCase.contains("test_version:")) {
                            nvtVulnerableRangeVersion1 = getTestVersionParameter(patternTestVersion, lineWithoutSpaceChars);
                        }
                        if (lineWithoutSpaceCharsLowerCase.endsWith(",")) {
                            isNotCompletedVersionInRangeFound = true;
                            printWriter.println(line);
                            continue;
                        }
                        nvtVulnerableRangeVersion2 = getTestVersionParameter(patternTestVersion2, lineWithoutSpaceChars);
                    }
                    //For version_is_less_equal, vulnerable_range = "Less than or equal to test_version"
                    matcherVersion = patternVersionIsLessEqual.matcher(lineWithoutSpaceChars);
                    if (matcherVersion.find())
                    {
                        versionFunction = VersionFunction.VERSION_IS_LESS_EQUAL;
                        nvtVersionVariable = matcherVersion.group(1);
                        nvtVulnerableRangeVersion1 = getTestVersionParameter(patternTestVersion, lineWithoutSpaceChars);
                    }
                    //For version_is_equal, vulnerable_range = "Equal to test_version"
                    matcherVersion = patternVersionIsEqual.matcher(lineWithoutSpaceChars);
                    if (matcherVersion.find())
                    {
                        versionFunction = VersionFunction.VERSION_IS_EQUAL;
                        nvtVersionVariable = matcherVersion.group(1);
                        nvtVulnerableRangeVersion1 = getTestVersionParameter(patternTestVersion, lineWithoutSpaceChars);
                    }
                }
                //In some of version_in_range function calls have newline separated parameters. This occurs in only version_in_range.
                //Example: gb_mozilla_firefox_esr_mult_vuln01_dec13_win.nasl
                if (isNotCompletedVersionInRangeFound) {
                    if (lineWithoutSpaceCharsLowerCase.contains("test_version:")) {
                        nvtVulnerableRangeVersion1 = getTestVersionParameter(patternTestVersion, lineWithoutSpaceChars);
                    }
                    if (lineWithoutSpaceCharsLowerCase.contains("test_version2:")) {
                        nvtVulnerableRangeVersion2 = getTestVersionParameter(patternTestVersion2, lineWithoutSpaceChars);
                    }
                    if (lineWithoutSpaceCharsLowerCase.endsWith(",")) {
                        printWriter.println(line);
                        continue;
                    }
                    isNotCompletedVersionInRangeFound = false;
                }
                if (isScannerInVersionCheck && line.contains("security_message")) {
                    String portParameter = "0";
                    Matcher matcherPortParameter = patternPortParameter.matcher(lineWithoutSpaceChars);
                    if (matcherPortParameter.find()) {
                        portParameter = matcherPortParameter.group(1);
                    }

                    isSecurityMessageFound = true;

                    String leadingSpaceChars = line.substring(0, line.indexOf("security_message"));
                    String report = createReportCode(versionFunction, nvtVersionVariable, nvtFixedVersion, nvtVulnerableRangeVersion1, nvtVulnerableRangeVersion2, nvtPath);
                    printWriter.println(leadingSpaceChars + report);
                    printWriter.println(leadingSpaceChars + "security_message(port: "+portParameter+", data: report);");
                }
                else {
                    printWriter.println(line);
                }
            }
            printWriter.close();
            if ( (!isAnyVersionCheckFunctionFound) || (!isSecurityMessageFound)) {
                System.out.println(file.getAbsolutePath());
                outputFile.delete();
            }
        }
    }

    private String createReportCode(VersionFunction versionFunction, String nvtVersionVariable, String nvtFixedVersion, String nvtVulnerableRangeVersion1, String nvtVulnerableRangeVersion2, String nvtPath) {
        String report = "report = report_fixed_ver(installed_version:"+nvtVersionVariable;
        if ( (versionFunction == VersionFunction.VERSION_IS_LESS) && (!nvtFixedVersion.equals("")) ) {
            report = report + ", fixed_version:" + nvtFixedVersion;
        }
        if ( (versionFunction == VersionFunction.VERSION_IN_RANGE) && (!nvtVulnerableRangeVersion1.equals("")) && (!nvtVulnerableRangeVersion2.equals("")) ) {
            report = report + ", vulnerable_range:" + nvtVulnerableRangeVersion1 + " + \" - \" + " + nvtVulnerableRangeVersion2;
        }
        if ( (versionFunction == VersionFunction.VERSION_IS_LESS_EQUAL) && (!nvtVulnerableRangeVersion1.equals("")) ) {
            report = report + ", vulnerable_range:" + "\"Less than or equal to \" + " + nvtVulnerableRangeVersion1;
        }
        if ( (versionFunction == VersionFunction.VERSION_IS_EQUAL) && (!nvtVulnerableRangeVersion1.equals("")) ) {
            report = report + ", vulnerable_range:" + "\"Equal to \" + " + nvtVulnerableRangeVersion1;        }
        if (!nvtPath.equals("")) {
            report = report + ", install_path:" + nvtPath;
        }
        report = report + ");";
        return report;

    }

    private String getTestVersionParameter(Pattern pattern, String lineWithoutSpaceChars) {
        String testVersion = "";
        Matcher matcherTestVersion = pattern.matcher(lineWithoutSpaceChars);
        if (matcherTestVersion.find()) {
            testVersion = matcherTestVersion.group(1);
        }
        return testVersion;
    }
}

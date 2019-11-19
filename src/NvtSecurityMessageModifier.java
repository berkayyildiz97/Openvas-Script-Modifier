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

    private final Pattern patternPortParameter = Pattern.compile("port:([^\\),]*)");

    private final Pattern patternOid =  Pattern.compile("script_oid\\(\"([^\"]*)\"\\);");

    private final Pattern patternPath = Pattern.compile("[^[,'=\")&+(/;]?]*path=.*;");

    public NvtSecurityMessageModifier(String nvtDirectoryPath, String nvtOidListPath, String outputDirectoryPath) {
        this.nvtDirectoryPath = nvtDirectoryPath;
        this.nvtOidListPath = nvtOidListPath;
        this.outputDirectoryPath = outputDirectoryPath;
    }

    private ArrayList<File> getNvtsShouldBeModified(ArrayList<File> allNvts) throws FileNotFoundException {
        ArrayList<String> targetOids = new ArrayList<>();
        Scanner scannerOids = new Scanner(new File(nvtOidListPath));
        while (scannerOids.hasNextLine()) {
            String line = scannerOids.nextLine();
            targetOids.add(line);
        }

        ArrayList<File> nvtsShouldBeModified = new ArrayList<>();
        for(File nvt : allNvts) {
            Scanner scanner = new Scanner(new BufferedReader(new FileReader(nvt)));
            boolean shouldNvtBeModified = true;
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                //If nvt contains "WillNotFix", it means that there is no fixed version.
                //If nvt contains "||", it means that there may be more than one version check functions in same if.
                if (line.contains("WillNotFix") || line.contains("||")) {
                    shouldNvtBeModified = false;
                    break;
                }

                if (line.contains("script_oid(")) {
                    Matcher matcherOid = patternOid.matcher(line);
                    String nvtOid = "";
                    if (matcherOid.find()) {
                        nvtOid = matcherOid.group(1);
                    }
                    if (!targetOids.contains(nvtOid)) {
                        shouldNvtBeModified = false;
                        break;
                    }
                }
            }
            scanner.close();
            if (shouldNvtBeModified) {
                nvtsShouldBeModified.add(nvt);
            }
        }
        return nvtsShouldBeModified;
    }

    public void modifyNvtSecurityMessages() throws FileNotFoundException {
        File folder = new File(nvtDirectoryPath);
        ArrayList<File> allNvts = new ArrayList<>();
        allNvts = getNVTFiles(folder, allNvts);

        ArrayList<File> nvts = getNvtsShouldBeModified(allNvts);

        ArrayList<String> targetOids = new ArrayList<>();
        Scanner scannerOids = new Scanner(new File(nvtOidListPath));
        while (scannerOids.hasNextLine()) {
            String line = scannerOids.nextLine();
            targetOids.add(line);
        }

        for(File file : nvts) {
            boolean isVersionChecked = false;
            boolean isSecurityMessageFound = false;
            String nvtVersionVariable = "";
            Scanner input = new Scanner(file);

            String nvtOid = "";
            String nvtPath = "";
            String nvtFixedVersion = "";
            boolean isNotCompletedVersionInRangeFound = false;

            boolean isVersionIsLessOrVersionInRangeFunctionFound = false;

            File outputFile = new File(outputDirectoryPath + "/" + file.getName());
            PrintWriter printWriter = new PrintWriter(outputFile);



            while (input.hasNextLine()) {
                String line = input.nextLine();
                String lineWithoutSpaceChars = line.replaceAll("\\s+","");
                String lineWithoutSpaceCharsLowerCase = lineWithoutSpaceChars.toLowerCase();

                if (lineWithoutSpaceChars.contains("script_oid(")) {
                    Matcher matcherOid = patternOid.matcher(lineWithoutSpaceChars);
                    if (matcherOid.find()) {
                        nvtOid = matcherOid.group(1);
                    }
                    if (!targetOids.contains(nvtOid)) {
                        break;
                    }
                }
                else if (lineWithoutSpaceCharsLowerCase.contains("path") && nvtPath.equals("")) {
                    Matcher matcherPath = patternPath.matcher(lineWithoutSpaceCharsLowerCase);
                    if (matcherPath.find() && lineWithoutSpaceCharsLowerCase.matches("[^[,'=\")&+(/;]?]*path=.*;")) {
                        String matchedStr = matcherPath.group();
                        nvtPath = matchedStr.substring(0, matchedStr.indexOf('='));
                        //nvtPath lowercase olan nvtPath değerini nvt'teki case durumuna getirmek için
                        int pathIndex = line.toLowerCase().indexOf(nvtPath);
                        nvtPath = line.substring(pathIndex, pathIndex + nvtPath.length());
                    }
                }
                //There are no fixed version patterns that I found in version_is_less_equal and version_is_equal functions. Fixed version is usually independent from checked version.
                //Example: secpod_trendmicro_officescan_dos_vuln.nasl
                //if (lineWithoutSpaceCharsLowerCase.contains("version_is_less(") || lineWithoutSpaceCharsLowerCase.contains("version_in_range(")) {
                if (lineWithoutSpaceCharsLowerCase.contains("version_is_less(")) {
                    isVersionIsLessOrVersionInRangeFunctionFound = true;
                    nvtFixedVersion = "";
                    String lineWithoutSpace = line.replaceAll("\\s+","");
                    Matcher matcherVersion = patternVersionIsLess.matcher(lineWithoutSpace);
                    //Fixed Version = test_version
                    if (matcherVersion.find())
                    {
                        isVersionChecked = true;
                        nvtVersionVariable = matcherVersion.group(1);
                        String lineAfterTestVersion = lineWithoutSpaceCharsLowerCase.substring(lineWithoutSpaceCharsLowerCase.indexOf("test_version:"));
                        nvtFixedVersion = lineAfterTestVersion.substring(lineAfterTestVersion.indexOf('\"') + 1, lineAfterTestVersion.indexOf(')') - 1);
                    }
                    //No fixed version should be produced for version_in_range function. Therefore below code is commented.
                    //Because some of them have fixed versions in solution header that is independent from the checked version range.
                    //Example :secpod_adobe_prdts_mem_crptn_vuln_win_jun11.nasl
//                    matcherVersion = patternVersionInRange.matcher(lineWithoutSpace);
//                    //Fixed Version = test_version2 (Add +1 to number after last dot )
//                    //If test_version and test_version both end with ".0", fixed version = test_version2 (Add +1 to number before last dot)
//                    if (matcherVersion.find())
//                    {
//                        isVersionChecked = true;
//                        nvtVersionVariable = matcherVersion.group(1);
//                        if (lineWithoutSpaceCharsLowerCase.endsWith(",")) {
//                            isNotCompletedVersionInRangeFound = true;
//                            printWriter.println(line);
//                            continue;
//                        }
//                        String lineAfterTestVersion2 = lineWithoutSpaceCharsLowerCase.substring(lineWithoutSpaceCharsLowerCase.indexOf("test_version2:"));
//                        String version2 = lineAfterTestVersion2.substring(lineAfterTestVersion2.indexOf('\"') + 1, lineAfterTestVersion2.indexOf(')') - 1);
//                        String[] version2Array = version2.split("\\.");
//                        try {
//                            if (version2Array[version2Array.length - 1].equals("0")) {
//                                String lineAfterTestVersion1 = lineWithoutSpaceCharsLowerCase.substring(lineWithoutSpaceCharsLowerCase.indexOf("test_version:"));
//                                String version1 = lineAfterTestVersion1.substring(lineAfterTestVersion1.indexOf('\"') + 1, lineAfterTestVersion1.indexOf(',') - 1);
//                                String[] version1Array = version1.split("\\.");
//                                if (version1Array[version1Array.length - 1].equals("0")) {
//                                    version2Array[version2Array.length - 2] = Integer.parseInt(version2Array[version2Array.length - 2]) + 1 + "";
//                                } else {
//                                    version2Array[version2Array.length - 1] = Integer.parseInt(version2Array[version2Array.length - 1]) + 1 + "";
//                                }
//                            } else {
//                                version2Array[version2Array.length - 1] = Integer.parseInt(version2Array[version2Array.length - 1]) + 1 + "";
//                            }
//                        //If the version contains letters like "b2", do not modify the script. Because fixed version cannot be determined.
//                        } catch (NumberFormatException e) {
//                            outputFile.delete();
//                            break;
//                        }
//
//
//                        for (int i = 0;i<version2Array.length;i++) {
//                            if (i == version2Array.length - 1) {
//                                nvtFixedVersion = nvtFixedVersion + version2Array[i];
//                            }
//                            else {
//                                nvtFixedVersion = nvtFixedVersion + version2Array[i] + ".";
//                            }
//                        }
//                    }
                }
//                if (isNotCompletedVersionInRangeFound) {
//                    String lineAfterTestVersion = lineWithoutSpaceCharsLowerCase.substring(lineWithoutSpaceCharsLowerCase.indexOf("test_version2:"));
//                    nvtFixedVersion = lineAfterTestVersion.substring(lineAfterTestVersion.indexOf('\"') + 1, lineAfterTestVersion.indexOf(')') - 1);
//                    isNotCompletedVersionInRangeFound = false;
//                }
                if (isVersionChecked && line.contains("security_message")) {
                    String portParameter = "0";
                    Matcher matcherPortParameter = patternPortParameter.matcher(lineWithoutSpaceChars);
                    if (matcherPortParameter.find()) {
                        portParameter = matcherPortParameter.group(1);
                    }

                    isSecurityMessageFound = true;

                    String leadingSpaceChars = line.substring(0, line.indexOf("security_message"));
                    if (nvtPath.equals("")) {
                        printWriter.println(leadingSpaceChars + "report = report_fixed_ver(installed_version:"+nvtVersionVariable+", fixed_version:\""+nvtFixedVersion+"\");");
                    }
                    else {
                        printWriter.println(leadingSpaceChars + "report = report_fixed_ver(installed_version:"+nvtVersionVariable+", fixed_version:\""+nvtFixedVersion+"\", install_path:"+nvtPath+");");
                    }
                    printWriter.println(leadingSpaceChars + "security_message(port: "+portParameter+", data: report);");
                }
                else {
                    printWriter.println(line);
                }
                if (isVersionChecked && line.contains("}")) {
                    isVersionChecked = false;
                }
            }
            printWriter.close();
            if ( (!isVersionIsLessOrVersionInRangeFunctionFound) || (!isSecurityMessageFound)) {
                outputFile.delete();
            }
        }
    }

    private ArrayList<File> getNVTFiles(File folder, ArrayList<File> listOfNvtPaths) {
        if (folder.isFile()) {
            if (folder.getName().endsWith(".nasl"))
                listOfNvtPaths.add(folder);
            return listOfNvtPaths;
        } else if (folder.isDirectory()) {
            File[] arrayOfFiles = folder.listFiles();

            for (int i = 0; i < arrayOfFiles.length; i++) {
                if (arrayOfFiles[i].isFile()) {
                    if (arrayOfFiles[i].getName().endsWith(".nasl"))
                        listOfNvtPaths.add(arrayOfFiles[i]);
                } else if (arrayOfFiles[i].isDirectory()) {
                    getNVTFiles(arrayOfFiles[i], listOfNvtPaths);
                }
            }
        }
        return listOfNvtPaths;
    }
}

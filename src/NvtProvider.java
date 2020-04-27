import java.io.*;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NvtProvider {

    private final Pattern patternOid =  Pattern.compile("script_oid\\(\"([^\"]*)\"\\);");

    private final Pattern patternPortVariable = Pattern.compile("([^[,'=\")&+(/;!]?]*port[^[,'=\")&+(/;!]?*]*)=get_[^_]*_port\\(", Pattern.CASE_INSENSITIVE);

    public final static Pattern patternCpeVariable = Pattern.compile("([^[,'=\")&+(/;!]?]*cpe[^[(64)(list)[,'=\")&+(/;!]]?*]*)=", Pattern.CASE_INSENSITIVE);

    public final static String portProducibleNvtFileListPath = "data/port_producible_nvt_oid_list";

    private final Pattern patternVersionIsLess = Pattern.compile("if\\(version_is_less\\(version:([^,]*)");

    private final Pattern patternVersionInRange = Pattern.compile("if\\(version_in_range\\(version:([^,]*)");

    private final Pattern patternVersionIsLessEqual = Pattern.compile("if\\(version_is_less_equal\\(version:([^,]*)");

    private final Pattern patternVersionIsEqual = Pattern.compile("if\\(version_is_equal\\(version:([^,]*)");

    public ArrayList<File> getNVTFiles(String nvtDirectoryPath) {
        File folder = new File(nvtDirectoryPath);
        ArrayList<File> allNvts = new ArrayList<>();
        allNvts = getNVTFilesHelper(folder, allNvts);
        return allNvts;
    }

    private ArrayList<File> getNVTFilesHelper(File folder, ArrayList<File> listOfNvtPaths) {
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
                    getNVTFilesHelper(arrayOfFiles[i], listOfNvtPaths);
                }
            }
        }
        return listOfNvtPaths;
    }

    public ArrayList<File> getNvtsShouldBeModified(ArrayList<File> allNvts, String nvtOidListPath) throws FileNotFoundException {
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
                //If nvt contains "||" or "&&", it means that there may be more than one version check functions in same if.
                if (line.contains("WillNotFix") || line.contains("||") || line.contains("&&")) {
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

    public void dumpPortProducibleNvtFileList(String nvtDirectoryPath) throws IOException {
        ArrayList<File> allNvts = getNVTFiles(nvtDirectoryPath);
        ArrayList<File> portProducibleNvtFileList = new ArrayList<>();
        for (File nvt : allNvts) {
            Scanner scanner = new Scanner(new BufferedReader(new FileReader(nvt)));
            String portVariable = "";
            String cpeVariable = "";
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                String lineWithoutSpaceChars = line.replaceAll("\\s+","");
                String lineWithoutSpaceCharsLowerCase = lineWithoutSpaceChars.toLowerCase();
                Matcher matcherPortVariable = patternPortVariable.matcher(lineWithoutSpaceChars);
                if (lineWithoutSpaceCharsLowerCase.contains("port") && matcherPortVariable.find()) {
                    portVariable = matcherPortVariable.group(1);
                }
                Matcher matcherCpeVariable = patternCpeVariable.matcher(lineWithoutSpaceChars);
                if (lineWithoutSpaceCharsLowerCase.contains("cpe") && matcherCpeVariable.find()) {
                    cpeVariable = matcherCpeVariable.group(1);
                }
                if (line.contains("security_message(") && portVariable.equals("") && (!cpeVariable.equals("")) ) {
                    portProducibleNvtFileList.add(nvt);
                    scanner.close();
                    break;
                }
            }
            scanner.close();
        }

        FileOutputStream fileOutputStream = new FileOutputStream(new File(portProducibleNvtFileListPath));
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
        objectOutputStream.writeObject(portProducibleNvtFileList);
        objectOutputStream.close();
    }

    public void updateUndetailedMessageNvtOidList(String nvtDirectoryPath, String nvtOidListPath) throws FileNotFoundException {
        ArrayList<File> allNvts = getNVTFiles(nvtDirectoryPath);

        ArrayList<String> listNVTsGivingUndetailedMessage = new ArrayList<>();

        for (File file : allNvts) {
            boolean isVersionChecked = false;
            String nvtVersionVariable = "";
            Scanner input = new Scanner(file);

            String nvtOid = "";

            while (input.hasNextLine()) {
                String line = input.nextLine();
                String lineWithoutSpaceChars = line.replaceAll("\\s+","");

                if (lineWithoutSpaceChars.contains("script_oid(")) {
                    Matcher matcherOid = patternOid.matcher(lineWithoutSpaceChars);
                    if (matcherOid.find()) {
                        nvtOid = matcherOid.group(1);
                    }
                }
                if (isVersionChecked && line.contains(nvtVersionVariable)) {
                    break;
                }
                if (line.contains("version_is_less") || line.contains("version_in_range") || line.contains("version_is_less_equal") || line.contains("version_is_equal")) {
                    String lineWithoutSpace = line.replaceAll("\\s+","");
                    Matcher matcherVersion = patternVersionIsLess.matcher(lineWithoutSpace);
                    if (matcherVersion.find())
                    {
                        isVersionChecked = true;
                        nvtVersionVariable = matcherVersion.group(1);
                    }
                    matcherVersion = patternVersionInRange.matcher(lineWithoutSpace);
                    if (matcherVersion.find())
                    {
                        isVersionChecked = true;
                        nvtVersionVariable = matcherVersion.group(1);
                    }
                    matcherVersion = patternVersionIsLessEqual.matcher(lineWithoutSpace);
                    if (matcherVersion.find())
                    {
                        isVersionChecked = true;
                        nvtVersionVariable = matcherVersion.group(1);
                    }
                    matcherVersion = patternVersionIsEqual.matcher(lineWithoutSpace);
                    if (matcherVersion.find())
                    {
                        isVersionChecked = true;
                        nvtVersionVariable = matcherVersion.group(1);
                    }
                }
                if (isVersionChecked && line.contains("}")) {
                    boolean isReportFixedVerOrManualMessageFound = false;
                    Scanner scanner2 = new Scanner(file);
                    while (scanner2.hasNextLine()) {
                        String line2 = scanner2.nextLine().toLowerCase();
                        if (line2.contains("report_fixed_ver") || line2.contains("'file checked:") || line2.contains("\\n'file checked:")
                                || line2.contains("'fixed version:") || line2.contains("'\\nfixed version:")
                                || line2.contains("'installed version:") || line2.contains("'\\ninstalled version:")) {
                            isReportFixedVerOrManualMessageFound = true;
                            break;
                        }
                    }
                    if (!isReportFixedVerOrManualMessageFound) {
                        if (!listNVTsGivingUndetailedMessage.contains(nvtOid)) {
                            listNVTsGivingUndetailedMessage.add(nvtOid);
                        }
                        break;
                    }
                }
            }
        }
        PrintWriter printWriter = new PrintWriter(nvtOidListPath);
        for (String oid : listNVTsGivingUndetailedMessage) {
            printWriter.println(oid);
        }
        printWriter.close();
    }
}

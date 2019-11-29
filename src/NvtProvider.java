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
}

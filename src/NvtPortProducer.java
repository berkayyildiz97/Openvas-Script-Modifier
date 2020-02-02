import java.io.*;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NvtPortProducer {
    private String outputDirectoryPath = "";

    private final String portProducibleNvtFileListPath = NvtProvider.portProducibleNvtFileListPath;

    private final Pattern patternCpeVariable = NvtProvider.patternCpeVariable;

    private final Pattern patternSecurityMessageParameters = Pattern.compile("security_message\\((.*)\\);");

    public NvtPortProducer(String outputDirectoryPath) {
        this.outputDirectoryPath = outputDirectoryPath;
    }

    public void producePortForSecurityMessage(String nvtDirectoryPath) throws IOException, ClassNotFoundException {
        FileInputStream fileInputStream = new FileInputStream(new File(portProducibleNvtFileListPath));
        ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
        ArrayList<File> portProducibleNvtFileList = (ArrayList<File>) objectInputStream.readObject();
        objectInputStream.close();
        for (File nvt : portProducibleNvtFileList) {
            Scanner scanner = new Scanner(new BufferedReader(new FileReader(nvt)));

            String cpeVariable = "";
            boolean isCpeFound = false;
            String nvtParentPath = nvt.getParentFile().getAbsolutePath();
            File outputFile = null;
            if (nvtParentPath.equals(nvtDirectoryPath)) {
                outputFile = new File(outputDirectoryPath + "/" + nvt.getName());
            }
            else {
                File nvtDirectoryFile = new File(nvtDirectoryPath);
                String nvtDirectoryName = nvtDirectoryFile.getName();
                String nvtDirectoryPathAfterPlugins = nvtParentPath.substring(nvtParentPath.indexOf(nvtDirectoryName) + nvtDirectoryName.length() + 1);
                //To create directories of nvt
                new File(outputDirectoryPath + "/" + nvtDirectoryPathAfterPlugins).mkdirs();
                outputFile = new File(outputDirectoryPath + "/" + nvtDirectoryPathAfterPlugins + "/" + nvt.getName());
            }
            PrintWriter printWriter = new PrintWriter(outputFile);

            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                String lineWithoutSpaceChars = line.replaceAll("\\s+", "");
                String lineWithoutSpaceCharsLowerCase = lineWithoutSpaceChars.toLowerCase();
                Matcher matcherCpeVariable = patternCpeVariable.matcher(lineWithoutSpaceChars);
                if (lineWithoutSpaceCharsLowerCase.contains("cpe") && matcherCpeVariable.find()) {
                    cpeVariable = matcherCpeVariable.group(1);
                    isCpeFound = true;
                }
                if (isCpeFound && line.contains("security_message")) {
                    String leadingSpaceChars = line.substring(0, line.indexOf("security_message"));
                    String getAppPortCall = "if(!port = get_app_port(cpe: "+cpeVariable+")) port = 0;";
                    printWriter.println(leadingSpaceChars + getAppPortCall);
                    printWriter.println(createSecurityMessageCallWithProducedPort(lineWithoutSpaceChars, leadingSpaceChars));
                }
                else {
                    printWriter.println(line);
                }
            }
            printWriter.close();
        }
    }
    private String createSecurityMessageCallWithProducedPort(String lineWithoutSpaceChars, String leadingSpaceChars) {
        Matcher matcherSecurityMessageParameters = patternSecurityMessageParameters.matcher(lineWithoutSpaceChars);
        String parameters = "";
        if (matcherSecurityMessageParameters.find()) {
            parameters = matcherSecurityMessageParameters.group(1);
        }
        StringBuilder securityMessageCall = new StringBuilder(leadingSpaceChars + "security_message(port:port");
        String[] parametersArray = parameters.split(",");
        for (String parameter : parametersArray) {
            if (parameter.startsWith("port:")) {
                continue;
            }
            securityMessageCall.append(", ").append(parameter);
        }
        securityMessageCall.append(");");
        return securityMessageCall.toString();
    }
}

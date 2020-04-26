import java.io.FileNotFoundException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainNvtSecurityMessageModifier {
    public static void main(String[] args) {
        String nvtDirectoryPath = "/var/lib/openvas/plugins";
        //TODO: update nvt_oid_list
        String nvtOidListPath = "data/nvt_oid_list.txt";
        String outputDirectoryPath = "data/OpenvasModifiedScripts";
        NvtSecurityMessageModifier nvtSecurityMessageModifier = new NvtSecurityMessageModifier(nvtDirectoryPath, nvtOidListPath, outputDirectoryPath);
        try {
            nvtSecurityMessageModifier.modifyNvtSecurityMessages();
        } catch(FileNotFoundException e) {
            e.printStackTrace();
        }
    }
}

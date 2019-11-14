import java.io.FileNotFoundException;

public class MainNvtSecurityMessageModifier {
    public static void main(String[] args) {
        String nvtDirectoryPath = "/var/lib/openvas/plugins";
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

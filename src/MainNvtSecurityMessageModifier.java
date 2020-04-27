import java.io.FileNotFoundException;

public class MainNvtSecurityMessageModifier {
    public static void main(String[] args) {
        String nvtDirectoryPath = "/var/lib/openvas/plugins";
        String nvtOidListPath = "data/nvt_oid_list.txt";
        NvtProvider nvtProvider = new NvtProvider();
        String outputDirectoryPath = "data/OpenvasModifiedScripts";
        NvtSecurityMessageModifier nvtSecurityMessageModifier = new NvtSecurityMessageModifier(nvtDirectoryPath, nvtOidListPath, outputDirectoryPath);
        try {
            //If you have already updated nvt_oid_list.txt for given outputDirectoryPath, make below line comment for faster output.
            nvtProvider.updateUndetailedMessageNvtOidList(nvtDirectoryPath, nvtOidListPath);
            nvtSecurityMessageModifier.modifyNvtSecurityMessages();
        } catch(FileNotFoundException e) {
            e.printStackTrace();
        }
    }
}

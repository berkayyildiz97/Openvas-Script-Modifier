import java.io.IOException;

public class MainNvtPortProducer {
    public static void main(String[] args) {
        String outputDirectoryPath = "data/OpenvasPortProducedScripts";
        String nvtDirectoryPath = "/var/lib/openvas/plugins";
        NvtPortProducer nvtPortProducer = new NvtPortProducer(outputDirectoryPath);
        NvtProvider nvtProvider = new NvtProvider();
        try {
            //If you have already dumped port_producible_nvt_oid_list for given outputDirectoryPath, make below line comment for faster output.
            nvtProvider.dumpPortProducibleNvtFileList(nvtDirectoryPath);
            nvtPortProducer.producePortForSecurityMessage();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}

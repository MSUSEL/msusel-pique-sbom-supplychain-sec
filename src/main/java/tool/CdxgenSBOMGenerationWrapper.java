package tool;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import utilities.helperFunctions;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;

public class CdxgenSBOMGenerationWrapper implements IGenerationTool {

    private static final Logger LOGGER = LoggerFactory.getLogger(TrivyWrapper.class);

    /**
     * Initializes a new instance of the TrivySBOMGenerationWrapper class.
     */
    public CdxgenSBOMGenerationWrapper() {

    }

    /**
     * Generates an SBOM for a given project location using Trivy. The SBOM is created in the CycloneDX format
     * and saved to a predetermined directory under the project's root directory.
     * This method constructs the command to run Trivy with the necessary arguments to produce the SBOM,
     * executes the command, and logs the process and potential errors.
     *
     * @param projectLocation The file path of the project directory for which to generate the SBOM.
     */
    public void generate(Path projectLocation, String genTool) {
        LOGGER.info("Trivy Generation --- Generating SBOM for {}", projectLocation.toString());

        File generatedSbom = new File(System.getProperty("user.dir") + "/input/projects/SBOM/sbom-cdxgen-cdx-" + projectLocation.getFileName() + ".json");
        String spec = "cyclonedx"; // output format

        // command for running cdxgen SBOM generation on the command line
        // because cdxgen does not take an input path we need to run this as a subshell command
        String[] cmd = {"(cd", projectLocation.toAbsolutePath().toString(),
                        "&&",
                        "cdxgen",
                        "--output", generatedSbom.toPath().toAbsolutePath().toString(),
                        ")"};
        String[] cmd2 = {"(cd "  + projectLocation.toAbsolutePath().toString() + " && cdxgen --output " + generatedSbom.toPath().toAbsolutePath().toString() +")"};

                //generatedSbom.toPath().toAbsolutePath().toString(), // output path
                //projectLocation.toAbsolutePath().toString() // product under analysis path
        LOGGER.info(Arrays.toString(cmd));
        // runs the command built above and captures the output, cdxgen itself will handle the file saving
        try {
            helperFunctions.getOutputFromProgram(cmd2,LOGGER);
            LOGGER.info("Exporting SBOM to: {}", generatedSbom.toPath());
            System.out.println("Exporting SBOM to: " + generatedSbom.toPath());
        } catch (IOException e) {
            LOGGER.error("Failed to run cdxgen for SBOM generation");
            LOGGER.error(e.toString());
            e.printStackTrace();
        }
    }
}

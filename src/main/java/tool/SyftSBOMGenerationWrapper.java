package tool;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import utilities.helperFunctions;

public class SyftSBOMGenerationWrapper implements IGenerationTool {
    private static final Logger LOGGER = LoggerFactory.getLogger(TrivyWrapper.class);

    /**
     * Initializes a new instance of the TrivySBOMGenerationWrapper class.
     */
    public SyftSBOMGenerationWrapper() {

    }

    /**
     * Generates an SBOM for a given project location using Trivy. The SBOM is created in the CycloneDX format
     * and saved to a predetermined directory under the project's root directory.
     * This method constructs the command to run Syft with the necessary arguments to produce the SBOM,
     * executes the command, and logs the process and potential errors.
     *
     * @param projectLocation The file path of the project directory for which to generate the SBOM.
     */
    public void generate(Path projectLocation, String genTool) {
        LOGGER.info("Syft Generation --- Generating SBOM for {}", projectLocation.toString());

        File generatedSbom = new File(System.getProperty("user.dir") + "/input/projects/SBOM/sbom-syft-cdx-" + projectLocation.getFileName() + ".json");
        String spec = "cyclonedx-json"; // output format

        // command for running syft SBOM generation on the command line
        // TODO: update Syft version such that it generates CDX 1.6 with this command
        if (genTool.contains("fs")) {
            String[] cmd = {"syft",
                    projectLocation.toAbsolutePath().toString(),
                    "--file", generatedSbom.toPath().toAbsolutePath().toString(),
                    "-o", spec};
            LOGGER.info(Arrays.toString(cmd));
            // runs the command built above and captures the output, trivy itself will handle the file saving
            try {
                helperFunctions.getOutputFromProgram(cmd,LOGGER);
                LOGGER.info("Exporting SBOM to: {}", generatedSbom.toPath());
                System.out.println("Exporting SBOM to: " + generatedSbom.toPath());
            } catch (IOException e) {
                LOGGER.error("Failed to run syft for SBOM generation");
                LOGGER.error(e.toString());
                e.printStackTrace();
            }
        }
        else if (genTool.contains("image")) {
            String[] cmd = {"syft",
                    projectLocation.toAbsolutePath().toString(),
                    "--file", generatedSbom.toPath().toAbsolutePath().toString(),
                    "-o", spec};
            LOGGER.info(Arrays.toString(cmd));
            // runs the command built above and captures the output, trivy itself will handle the file saving
            try {
                helperFunctions.getOutputFromProgram(cmd,LOGGER);
                LOGGER.info("Exporting SBOM to: {}", generatedSbom.toPath());
                System.out.println("Exporting SBOM to: " + generatedSbom.toPath());
            } catch (IOException e) {
                LOGGER.error("Failed to run syft for SBOM generation");
                LOGGER.error(e.toString());
                e.printStackTrace();
            }
        }

    }


}

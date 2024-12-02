package tool;

import java.nio.file.Path;

/**
 * Interface definition for SBOM generation tools
 */
public interface IGenerationTool {
    /**
     * Generates an SBOM for a given project location using Trivy. The SBOM is created in the CycloneDX format
     * and saved to a predetermined directory under the project's root directory.
     * This method constructs the command to run Syft with the necessary arguments to produce the SBOM,
     * executes the command, and logs the process and potential errors.
     *
     * @param projectLocation The file path of the project directory for which to generate the SBOM.
     */
    void generate(Path projectLocation, String genTool);

}

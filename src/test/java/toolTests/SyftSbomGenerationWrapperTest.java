package toolTests;

import org.junit.jupiter.api.Test;
import pique.utility.PiqueProperties;
import tool.SyftSbomGenerationWrapper;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class SyftSbomGenerationWrapperTest {

    @Test
    public void testGenerateSource() throws IOException {
        // Arrange
        Properties prop = PiqueProperties.getProperties("/home/eric/Documents/research/PIQUE-SBOM-dev/current/msusel-pique-sbom-supplychain-sec/src/test/resources/pique-properties-TEST.properties");
        String sourceCodeInputPath = prop.getProperty("project.source-code-input");
        Path sourceCodePath = Paths.get(sourceCodeInputPath);

        Set<Path> sourceCodeRoots = new HashSet<>();
        File[] sourceCodeToGenerateSbomsFrom = sourceCodePath.toFile().listFiles();
        assert sourceCodeToGenerateSbomsFrom != null; // Ensure the directory is not empty
        for (File f : sourceCodeToGenerateSbomsFrom) {
            if (!f.getName().equals(".gitignore")) { // Check to avoid adding .gitignore
                sourceCodeRoots.add(f.toPath()); // Add both files and directories except .gitignore
            }
        }

        SyftSbomGenerationWrapper sbomGenerator = new SyftSbomGenerationWrapper();

        // Act
        for (Path root : sourceCodeRoots) {
            sbomGenerator.generateSource(root);

            // Assert
            File generatedSbom = new File(System.getProperty("user.dir") + "/input/projects/SBOM/sbom-syft-cdx-" + root.getFileName() + ".json");
            assertTrue(generatedSbom.exists(), "SBOM should be generated for " + root);

            // Validate JSON structure
            String sbomContent = Files.readString(generatedSbom.toPath());
            assertDoesNotThrow(() -> new org.json.JSONObject(sbomContent), "Generated SBOM should be valid JSON for " + root);
        }
    }

    @Test
    public void testGenerateImage() throws IOException {
        // Arrange
        Properties prop = PiqueProperties.getProperties("/home/eric/Documents/research/PIQUE-SBOM-dev/current/msusel-pique-sbom-supplychain-sec/src/test/resources/pique-properties-TEST.properties");
        String imageInputPath = prop.getProperty("project.image-input");
        Path imagesPath = Paths.get(imageInputPath);

        Set<Path> imageRoots = new HashSet<>();
        File[] imagesToGenerateSbomsFrom = imagesPath.toFile().listFiles();
        assert imagesToGenerateSbomsFrom != null; // Ensure the directory is not empty
        for (File f : imagesToGenerateSbomsFrom) {
            if (!f.getName().equals(".gitignore")) { // Check to avoid adding .gitignore
                imageRoots.add(f.toPath()); // Add both files and directories except .gitignore
            }
        }

        SyftSbomGenerationWrapper sbomGenerator = new SyftSbomGenerationWrapper();

        // Act
        for (Path root : imageRoots) {
            sbomGenerator.generateImage(root);

            // Assert
            File generatedSbom = new File(System.getProperty("user.dir") + "/input/projects/SBOM/sbom-syft-cdx-" + root.getFileName() + ".json");
            assertTrue(generatedSbom.exists(), "SBOM should be generated for " + root);

            // Validate JSON structure
            String sbomContent = Files.readString(generatedSbom.toPath());
            assertDoesNotThrow(() -> new org.json.JSONObject(sbomContent), "Generated SBOM should be valid JSON for " + root);
        }
    }
}

package toolTests;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Properties;

import org.junit.Test;

import pique.analysis.Tool;
import pique.model.Diagnostic;
import pique.utility.PiqueProperties;
import tool.CveBinToolWrapper;
import tool.TrivyWrapper;

import static org.junit.Assert.*;

public class CveBinToolTest {
    @Test
    public void TestSBOMWithFindings() {
        Properties prop = PiqueProperties.getProperties();
        Tool cveBinToolTest = new CveBinToolWrapper();

        Path testSBOM = Paths.get("src/test/resources/benchmark/S1.json");

        //Path analysisOutput = cveBinToolTest.analyze(testSBOM);
        File tempResults = new File(System.getProperty("user.dir") + "/out/cve_bin_tool.json");
        Path analysisOutput = tempResults.toPath();

        Map<String, Diagnostic> output = cveBinToolTest.parseAnalysis(analysisOutput);

        assertTrue(output!=null);
        assertTrue(output.size()>0);

        for (Diagnostic diag : output.values()) {
            if (diag.getChildren().size()>0) {
                //if we hit this, we've found at least one finding
                return;
            }
        }
        //if we didn't return from the above statement, force the test to fail
        fail();
    }

    @Test
    public void TestSBOMWithNoFindings() {
        Properties prop = PiqueProperties.getProperties();
        String ghTokenPath = Paths.get(prop.getProperty("github-token-path")).toString();
        Tool trivyTest = new TrivyWrapper(ghTokenPath);

        Path testSBOM = Paths.get("src/test/resources/benchmark/empty_sbom.json");

        Path analysisOutput = trivyTest.analyze(testSBOM);

        Map<String,Diagnostic> output = trivyTest.parseAnalysis(analysisOutput);

        for (Diagnostic diag : output.values()) {
            if (diag.getChildren().size()>0) {
                //if we hit this, we've found at least one finding
                fail();
            }
        }
    }

    @Test
    public void TestNoFindingsWhenNoSBOMExists() {
        Properties prop = PiqueProperties.getProperties();
        String ghTokenPath = Paths.get(prop.getProperty("github-token-path")).toString();
        Tool trivyTest = new TrivyWrapper(ghTokenPath);

        Path testSBOM = Paths.get("src/test/resources/benchmark");

        Path analysisOutput = trivyTest.analyze(testSBOM);

        Map<String,Diagnostic> output = trivyTest.parseAnalysis(analysisOutput);

        for (Diagnostic diag : output.values()) {
            if (diag.getChildren().size()>0) {
                //if we hit this, we've found at least one finding
                fail();
            }
        }
    }

    @Test
    public void TestSBOMDoesNotExist() {
        Properties prop = PiqueProperties.getProperties();
        String ghTokenPath = Paths.get(prop.getProperty("github-token-path")).toString();
        Tool trivyTest = new TrivyWrapper(ghTokenPath);

        Path testSBOM = Paths.get("src/test/resources/benchmark/test.json");

        Path analysisOutput = trivyTest.analyze(testSBOM);

        Map<String,Diagnostic> output = trivyTest.parseAnalysis(analysisOutput);

        for (Diagnostic diag : output.values()) {
            if (diag.getChildren().size()>0) {
                //if we hit this, we've found at least one finding
                fail();
            }
        }
    }
}

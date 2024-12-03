package toolTests;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Properties;

import org.junit.Ignore;
import org.junit.Test;

import pique.analysis.Tool;
import pique.model.Diagnostic;
import pique.utility.PiqueProperties;
import presentation.PiqueData;
import presentation.PiqueDataFactory;
import tool.GrypeWrapper;
import tool.TrivyWrapper;
import tool.sbomqsWrapper;


import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class GrypeWrapperTest {
    private final PiqueData piqueData = new PiqueDataFactory().getPiqueData();

    @Test
    public void TestSBOMWithFindings() {
        Properties prop = PiqueProperties.getProperties();
        Tool grypeTest = new GrypeWrapper(piqueData);

        Path testSBOM = Paths.get("src/test/resources/benchmark/S1.json");

        Path analysisOutput = grypeTest.analyze(testSBOM);

        Map<String,Diagnostic> output = grypeTest.parseAnalysis(analysisOutput);

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
    public void SBOMQSTestSBOMWithFindings() {
        sbomqsWrapper sbomqsTest = new sbomqsWrapper();

        Path testSBOM = Paths.get("src/test/resources/benchmark/S1.json");

        Path analysisOutput = sbomqsTest.analyze(testSBOM);

        Map<String, Diagnostic> output = sbomqsTest.parseAnalysis(analysisOutput);

        assertTrue(output!=null);
    }

    @Test
    public void TestSBOMWithNoFindings() {
        Properties prop = PiqueProperties.getProperties();
        Tool grypeTest = new GrypeWrapper(piqueData);

        Path testSBOM = Paths.get("src/test/resources/benchmark/empty_sbom.json");

        Path analysisOutput = grypeTest.analyze(testSBOM);

        Map<String,Diagnostic> output = grypeTest.parseAnalysis(analysisOutput);

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
        Tool grypeTest = new GrypeWrapper(piqueData);

        Path testSBOM = Paths.get("src/test/resources/benchmark");

        Path analysisOutput = grypeTest.analyze(testSBOM);

        Map<String,Diagnostic> output = grypeTest.parseAnalysis(analysisOutput);

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
        Tool grypeTest = new GrypeWrapper(piqueData);

        Path testSBOM = Paths.get("src/test/resources/benchmark/test.json");

        Path analysisOutput = grypeTest.analyze(testSBOM);

        Map<String,Diagnostic> output = grypeTest.parseAnalysis(analysisOutput);

        for (Diagnostic diag : output.values()) {
            if (diag.getChildren().size()>0) {
                //if we hit this, we've found at least one finding
                fail();
            }
        }
    }
}

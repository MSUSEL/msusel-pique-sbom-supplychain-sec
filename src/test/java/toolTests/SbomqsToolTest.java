package toolTests;

import org.junit.Test;
import pique.analysis.Tool;
import pique.model.Diagnostic;
import pique.utility.PiqueProperties;
import tool.CveBinToolWrapper;
import tool.TrivyWrapper;
import tool.sbomqsWrapper;
import utilities.helperFunctions;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Properties;

import static org.junit.Assert.*;

public class SbomqsToolTest {
    @Test
    public void TestSBOMWithFindings() {
        Properties prop = PiqueProperties.getProperties();
        Tool sbomqsToolTest = new sbomqsWrapper();

        Path testSBOM = Paths.get("src/test/resources/benchmark/S1.json");

        Path analysisOutput = sbomqsToolTest.analyze(testSBOM);

        int comps = helperFunctions.getComponentCount();

        assertEquals(comps, 185);

        //fail();
    }

}

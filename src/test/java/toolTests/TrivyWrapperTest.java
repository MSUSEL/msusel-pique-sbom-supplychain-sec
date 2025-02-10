/*
 * MIT License
 *
 * Copyright (c) 2023 Montana State University Software Engineering Labs
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package toolTests;

import org.junit.jupiter.api.Test;
import pique.analysis.Tool;
import pique.model.Diagnostic;
import pique.utility.PiqueProperties;
import presentation.PiqueData;
import presentation.PiqueDataFactory;
import tool.TrivyWrapper;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

public class TrivyWrapperTest {
    private final PiqueData piqueData = new PiqueDataFactory().getPiqueData();

    @Test
    public void TestSBOMWithFindings() {
        Properties prop = PiqueProperties.getProperties();
        Tool trivyTest = new TrivyWrapper(piqueData);

        Path testSBOM = Paths.get("src/test/resources/benchmark/S1.json");

        Path analysisOutput = trivyTest.analyze(testSBOM);

        Map<String, Diagnostic> output = trivyTest.parseAnalysis(analysisOutput);

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
        Tool trivyTest = new TrivyWrapper(piqueData);

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
        Tool trivyTest = new TrivyWrapper(piqueData);

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
        Tool trivyTest = new TrivyWrapper(piqueData);

        Path testSBOM = Paths.get("src/test/resources/benchmark/does_not_exist.json");

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

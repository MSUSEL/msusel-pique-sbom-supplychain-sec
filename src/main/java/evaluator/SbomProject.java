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
package evaluator;

import model.SbomDiagnostic;
import pique.evaluation.Project;
import pique.model.Diagnostic;
import pique.model.ModelNode;
import pique.model.QualityModel;

import java.nio.file.Path;
import java.util.Map;

public class SbomProject extends Project {

    public SbomProject(String name) {
        super(name);
    }

    public SbomProject(String name, QualityModel qm) {
        super(name, qm);
    }

    public SbomProject(String name, Path path, QualityModel qm) {
        super(name, path, qm);
    }

    /**
     * Taken from PIQUE core and modified to update the diagnostics packages field as well
     *
     * Find the diagnostic objects in this project and update their findings with findings containing in
     * the input parameter.  This method matches the diagnostic objects by name.
     *
     * @param diagnosticsWithFindings
     * 		A map {Key: diagnostic name, Value: diagnostic object} of diagnostics containing > 0 values of
     * 		findings.
     */
    public void updateDiagnosticsWithFindings(Map<String, Diagnostic> diagnosticsWithFindings) {
        // Iterate through each diagnostic in the diagnosticsWithFindings map
        for (Diagnostic diagnostic : diagnosticsWithFindings.values()) {
            // Iterate through each measure in the quality model's measures
            for (ModelNode measure : getQualityModel().getMeasures().values()) {
                // Iterate through each child diagnostic of the current measure
                for (ModelNode oldDiagnostic : measure.getChildren().values()) {
                    // Check if the name of the old diagnostic matches the name of the current diagnostic
                    if (oldDiagnostic.getName().equals(diagnostic.getName())) {
                        // Update the children of the old diagnostic with the children of the current diagnostic
                        oldDiagnostic.setChildren(diagnostic.getChildren());
                        // Update the packages of the old diagnostic with the packages of the current diagnostic
                        ((SbomDiagnostic) oldDiagnostic).setPackages(((SbomDiagnostic) diagnostic).getPackages());
                    }
                }
            }
        }
    }
}

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

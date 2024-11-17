/**
 * MIT License
 *
 * Copyright (c) 2024 Montana State University Software Engineering Labs
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
package model;

import com.google.gson.annotations.Expose;
import lombok.Getter;
import lombok.Setter;
import pique.evaluation.IEvaluator;
import pique.evaluation.INormalizer;
import pique.evaluation.IUtilityFunction;
import pique.model.Diagnostic;
import pique.model.ModelNode;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

public class SbomDiagnostic extends Diagnostic {


    @Getter
    @Expose
    private HashSet<String> packages;

    public SbomDiagnostic(String id, String description, String toolName, HashSet<String> packages) {
        super(id, description, toolName);
        this.packages = packages;
    }

    public SbomDiagnostic(String id, String description, String toolName, IEvaluator evaluator, HashSet<String> packages) {
        super(id, description, toolName, evaluator);
        this.packages = packages;
    }

    public SbomDiagnostic(String id, String description, String toolName, IEvaluator evaluator, INormalizer normalizer, IUtilityFunction utilityFunction, Map<String, BigDecimal> weights, BigDecimal[] thresholds, HashSet<String> packages) {
        super(id, description, toolName, evaluator, normalizer, utilityFunction, weights, thresholds);
        this.packages = packages;
    }

    public SbomDiagnostic(BigDecimal value, String name, String description, IEvaluator evaluator, INormalizer normalizer, IUtilityFunction utilityFunction, Map<String, BigDecimal> weights, BigDecimal[] thresholds, Map<String, ModelNode> children, HashSet<String> packages) {
        super(value, name, description, evaluator, normalizer, utilityFunction, weights, thresholds, children);
        this.packages = packages;
    }
    @Override
    public ModelNode clone() {

        Map<String, ModelNode> clonedChildren = new HashMap<>();
        getChildren().forEach((k, v) -> clonedChildren.put(k, v.clone()));

        return new SbomDiagnostic(getValue(), getName(), getDescription(), this.getEval_strategyObj(), this.getNormalizerObj(),
                this.getUtility_function(), getWeights(), getThresholds(), clonedChildren, this.packages);
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof SbomDiagnostic)) { return false; }
        SbomDiagnostic otherDiagnostic = (SbomDiagnostic) other;

        return getName().equals(otherDiagnostic.getName())
                && getToolName().equals(otherDiagnostic.getToolName());
    }

    public void updatePackages(String packageName, String packageVersion) {
        this.packages.add(packageName + ":" + packageVersion);
    }

    public void setPackages(HashSet<String> packages) {
        this.packages = packages;
    }
}
package com.netsentry.evaluation;

/** Calculates precision, recall, F1, and accuracy from a confusion matrix. */
public record EvaluationMetrics(long truePositive, long falsePositive, long falseNegative, long trueNegative) {

    public double precision() {
        return ratio(truePositive, truePositive + falsePositive);
    }

    public double recall() {
        return ratio(truePositive, truePositive + falseNegative);
    }

    public double f1() {
        return ratio(2.0 * precision() * recall(), precision() + recall());
    }

    public double accuracy() {
        return ratio(truePositive + trueNegative, truePositive + falsePositive + falseNegative + trueNegative);
    }

    private static double ratio(long numerator, long denominator) {
        return denominator == 0 ? 0.0 : (double) numerator / denominator;
    }

    private static double ratio(double numerator, double denominator) {
        return denominator == 0 ? 0.0 : numerator / denominator;
    }
}

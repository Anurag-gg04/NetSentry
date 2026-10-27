package com.netsentry.evaluation;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class EvaluationMetricsTest {

    @Test void calculatesPrecisionRecallF1AndAccuracy() {
        EvaluationMetrics metrics = new EvaluationMetrics(8, 2, 2, 18);
        assertEquals(0.8, metrics.precision(), 0.00001);
        assertEquals(0.8, metrics.recall(), 0.00001);
        assertEquals(0.8, metrics.f1(), 0.00001);
        assertEquals(0.8666667, metrics.accuracy(), 0.00001);
    }

    @Test void zeroDenominatorsReturnZeroRatherThanNan() {
        EvaluationMetrics metrics = new EvaluationMetrics(0, 0, 0, 0);
        assertEquals(0.0, metrics.precision());
        assertEquals(0.0, metrics.recall());
        assertEquals(0.0, metrics.f1());
        assertEquals(0.0, metrics.accuracy());
    }
}

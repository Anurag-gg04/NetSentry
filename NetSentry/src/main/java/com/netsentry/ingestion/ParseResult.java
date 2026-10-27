package com.netsentry.ingestion;

import com.netsentry.model.FlowRecord;
import java.util.ArrayList;
import java.util.List;

public class ParseResult {
    public final List<FlowRecord> records = new ArrayList<>();
    public final List<String> errors = new ArrayList<>();
    public long totalRows;
    public long rejectedRows;
}

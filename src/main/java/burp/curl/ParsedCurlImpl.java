package burp.curl;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** The {@link ParsedCurl} produced by {@link Curl#parse}. */
final class ParsedCurlImpl implements ParsedCurl {
    private final List<Operation> operations;
    private final List<Warning> warnings;

    ParsedCurlImpl(List<Operation> operations, List<Warning> warnings) {
        this.operations = List.copyOf(operations);
        this.warnings = List.copyOf(warnings);
    }

    @Override
    public List<String> fileRefs() {
        Set<String> refs = new LinkedHashSet<>();
        for (Operation op : operations) {
            for (Operation.DataPiece p : op.data) {
                if (p.file == null) {
                    continue;
                }
                if (p.file.equals("-")) {
                    if (op.stdin != null && op.stdin.bytes == null && op.stdin.file != null) {
                        refs.add(op.stdin.file);
                    }
                } else {
                    refs.add(p.file);
                }
            }
        }
        return new ArrayList<>(refs);
    }

    @Override
    public List<Warning> warnings() {
        return warnings;
    }

    @Override
    public List<BuiltRequest> build(FileAccess files) throws CurlParseException {
        List<BuiltRequest> out = new ArrayList<>();
        for (RequestDetails d : details(files)) {
            out.add(d.request());
        }
        return out;
    }

    /** Like {@link #build} but with the extra pieces the legacy facade needs. */
    List<RequestDetails> details(FileAccess files) throws CurlParseException {
        return CurlRequestBuilder.build(operations, files == null ? FileAccess.DENY : files);
    }
}

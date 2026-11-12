package burp.curl;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The {@link ParsedCurl} produced by {@link Curl#parse}. It keeps the argument words of every curl command and
 * parses them again when {@link #build} supplies the file access: variables ({@code --variable name@file}) can
 * change what an option means, so their files must be read before the operations are known.
 */
final class ParsedCurlImpl implements ParsedCurl {

    /** One curl command of the paste. */
    static final class Run {
        final CommandLine command;
        final List<Token> args;
        /** the operations of the parse without file contents (used for {@link #fileRefs()}) */
        final List<Operation> probeOps;
        /** the files variables read during that parse */
        final List<String> variableFiles;
        /** true when file variables can change what the options mean: the real parse is the authority */
        final boolean contentDependent;

        Run(CommandLine command, List<Token> args, List<Operation> probeOps, List<String> variableFiles,
            boolean contentDependent) {
            this.command = command;
            this.args = args;
            this.probeOps = probeOps;
            this.variableFiles = variableFiles;
            this.contentDependent = contentDependent;
        }
    }

    private final List<Run> runs;
    private final List<Warning> warnings;

    ParsedCurlImpl(List<Run> runs, List<Warning> warnings) {
        this.runs = List.copyOf(runs);
        this.warnings = List.copyOf(warnings);
    }

    @Override
    public List<String> fileRefs() {
        Set<String> refs = new LinkedHashSet<>();
        for (Run r : runs) {
            for (String f : r.variableFiles) {
                if (!f.isEmpty()) {
                    refs.add(f);
                }
            }
            for (Operation op : r.probeOps) {
                op.collectFileRefs(refs);
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
        try {
            return detailsUnguarded(files);
        } catch (CurlParseException e) {
            throw e;
        } catch (RuntimeException | StackOverflowError e) {
            throw new CurlParseException("The curl command could not be built (" + e + ")");
        }
    }

    /** {@link #details} without the safety net that turns unexpected runtime failures into parse exceptions. */
    List<RequestDetails> detailsUnguarded(FileAccess files) throws CurlParseException {
        // only the paths fileRefs() lists were shown to the user: nothing else is ever read
        FileAccess access = FileReads.guard(files == null ? FileAccess.DENY : files, new LinkedHashSet<>(fileRefs()));
        List<RequestDetails> result = new ArrayList<>();
        CurlRequestBuilder builder = new CurlRequestBuilder(access);
        for (Run r : runs) {
            CurlCommandParser.Parsed p = CurlCommandParser.parse(r.args, r.command, access, false);
            for (Operation op : p.operations) {
                if (r.contentDependent) {
                    op.lateWarnings.addAll(0, p.warnings);
                }
                builder.buildOperation(op, result);
            }
        }
        return result;
    }
}

package burp.curl;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Wording helpers that keep warnings and exception messages free of pasted values.
 *
 * <p>The rule for every message of this package: it may contain option names, shell variable names
 * ({@code $TOKEN}, {@code %USERPROFILE%}), local file paths and the {@code --resolve}/{@code --connect-to} argument;
 * never an argument value, a header name or value, a credential, a user name, a URL, a host, a body or the text of a
 * command substitution.
 */
final class MessageText {
    private static final Pattern PLAIN_VARIABLE = Pattern.compile("\\$(?:[A-Za-z_][A-Za-z0-9_]*|\\{[A-Za-z_][A-Za-z0-9_]*}"
            + "|[0-9@*#?$!-])");
    private static final Pattern VARIABLE_WITH_OPERATOR = Pattern.compile("\\$\\{([A-Za-z_][A-Za-z0-9_]*)[^}]*}?",
            Pattern.DOTALL);

    private MessageText() {
    }

    /**
     * @param expansion the text of a shell expansion as pasted: {@code $VAR}, {@code ${VAR}}, {@code ${VAR:-x}},
     *                  {@code $(cmd)}, {@code $((1+2))}, {@code `cmd`}, {@code <(cmd)}
     * @return a description that names a variable but never quotes a command or a default value
     */
    static String shellExpansion(String expansion) {
        if (PLAIN_VARIABLE.matcher(expansion).matches()) {
            return expansion;
        }
        Matcher m = VARIABLE_WITH_OPERATOR.matcher(expansion);
        if (m.matches()) {
            return "${" + m.group(1) + "...}";
        }
        if (expansion.startsWith("$((")) {
            return "an arithmetic expansion";
        }
        if (expansion.startsWith("<(") || expansion.startsWith(">(")) {
            return "a process substitution";
        }
        if (expansion.startsWith("${")) {
            return "a parameter expansion";
        }
        return "a command substitution";
    }

    /**
     * @param word an option word as pasted, possibly {@code --name=value}
     * @return the option name without any {@code =value}
     */
    static String optionName(String word) {
        int eq = word.indexOf('=');
        return eq < 0 ? word : word.substring(0, eq);
    }
}

package burp;

import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.util.List;
import java.util.function.Supplier;

/** Swing implementation of the dialogs. Must be used on the EDT. */
public final class SwingDialogs implements PasteCurlAction.Dialogs {
    private final Supplier<Component> parent;

    /** @param parent supplies the dialog parent (Burp's suite frame) */
    public SwingDialogs(Supplier<Component> parent) {
        this.parent = parent;
    }

    @Override
    public void info(String title, String message) {
        JOptionPane.showMessageDialog(parent.get(), message, title, JOptionPane.INFORMATION_MESSAGE);
    }

    @Override
    public void error(String title, String message) {
        JOptionPane.showMessageDialog(parent.get(), scroll(message), title, JOptionPane.ERROR_MESSAGE);
    }

    @Override
    public void warning(String title, String message) {
        JOptionPane.showMessageDialog(parent.get(), scroll(message), title, JOptionPane.WARNING_MESSAGE);
    }

    @Override
    public PasteCurlAction.FileChoice confirmFiles(List<PasteCurlAction.FileInfo> files) {
        String[] options = {"Read files", "Use placeholders", "Cancel"};
        int r = JOptionPane.showOptionDialog(parent.get(), scroll(fileConfirmationText(files, new LocalFiles().home().toString())),
                PasteCurlAction.TITLE + " - local files", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
                null, options, options[1]);
        return switch (r) {
            case 0 -> PasteCurlAction.FileChoice.READ_FILES;
            case 1 -> PasteCurlAction.FileChoice.USE_PLACEHOLDERS;
            default -> PasteCurlAction.FileChoice.CANCEL;
        };
    }

    /**
     * @param files the paths
     * @param home directory used for relative paths
     * @return the dialog text
     */
    static String fileConfirmationText(List<PasteCurlAction.FileInfo> files, String home) {
        StringBuilder sb = new StringBuilder();
        sb.append("The command reads local files. Burp will read them only if you choose \"Read files\".\n");
        sb.append("\"Use placeholders\" puts <<FILE: path>> into the request instead.\n\n");
        sb.append("Relative paths are resolved against your home directory (").append(home).append("),\n");
        sb.append("because curl would use the shell's working directory, which Burp cannot know.\n");
        for (PasteCurlAction.FileInfo f : files) {
            sb.append("\nAs written: ").append(f.written());
            sb.append("\nResolves to: ").append(f.resolved());
            sb.append("\nStatus: ").append(f.status()).append('\n');
        }
        return sb.toString();
    }

    private static JScrollPane scroll(String text) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setCaretPosition(0);
        JScrollPane pane = new JScrollPane(area);
        pane.setPreferredSize(new Dimension(640, Math.min(360, 40 + 16 * text.split("\n", -1).length)));
        return pane;
    }
}

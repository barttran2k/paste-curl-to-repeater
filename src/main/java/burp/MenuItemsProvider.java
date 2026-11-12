package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.awt.Toolkit;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.util.ArrayList;
import java.util.List;

/** Adds "Paste cURL command" to Burp's context menu and wires the flow to the real Swing/Montoya parts. */
public class MenuItemsProvider implements ContextMenuItemsProvider {

    private MontoyaApi api;

    public MenuItemsProvider() {
        //noop
    }

    public MenuItemsProvider(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItemList = new ArrayList<>();

        JMenuItem pasteItem = new JMenuItem("Paste cURL command");
        pasteItem.addActionListener(e -> createAction().run());

        menuItemList.add(pasteItem);
        return menuItemList;
    }

    private PasteCurlAction createAction() {
        LocalFiles files = new LocalFiles();
        return new PasteCurlAction(
                MenuItemsProvider::clipboardText,
                new SwingDialogs(() -> api.userInterface().swingUtils().suiteFrame()),
                new MontoyaRequestSink(api),
                new PasteCurlAction.Log() {
                    @Override
                    public void output(String message) {
                        api.logging().logToOutput(message);
                    }

                    @Override
                    public void error(Throwable t) {
                        api.logging().logToError(t);
                    }
                },
                files,
                () -> files);
    }

    /** @return the clipboard text, or null when the clipboard holds no text */
    static String clipboardText() throws Exception {
        Transferable transferable = Toolkit.getDefaultToolkit().getSystemClipboard().getContents(null);
        if (transferable != null && transferable.isDataFlavorSupported(DataFlavor.stringFlavor)) {
            return (String) transferable.getTransferData(DataFlavor.stringFlavor);
        }
        return null;
    }
}

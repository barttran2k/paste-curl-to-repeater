package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.curl.BuiltRequest;

/** Sends built requests to Repeater through the Montoya API. */
public final class MontoyaRequestSink implements PasteCurlAction.RequestSink {
    private final MontoyaApi api;

    /** @param api the Montoya API */
    public MontoyaRequestSink(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public void send(BuiltRequest request, String tabName) {
        HttpService service = HttpService.httpService(request.host(), request.port(), request.secure());
        HttpRequest http = HttpRequest.httpRequest(service, ByteArray.byteArray(request.raw()));
        if (tabName == null) {
            api.repeater().sendToRepeater(http);
        } else {
            api.repeater().sendToRepeater(http, tabName);
        }
    }
}

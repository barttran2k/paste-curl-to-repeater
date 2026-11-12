package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.repeater.Repeater;
import burp.curl.BuiltRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MontoyaRequestSinkTest {
    private MontoyaObjectFactory saved;
    private final List<Object[]> calls = new ArrayList<>();
    private final HttpService service = (HttpService) Proxy.newProxyInstance(getClass().getClassLoader(),
            new Class<?>[]{HttpService.class}, (p, m, a) -> m.getName().equals("hashCode") ? 1
                    : m.getName().equals("equals") ? p == a[0] : null);
    private final HttpRequest request = (HttpRequest) Proxy.newProxyInstance(getClass().getClassLoader(),
            new Class<?>[]{HttpRequest.class}, (p, m, a) -> m.getName().equals("hashCode") ? 2
                    : m.getName().equals("equals") ? p == a[0] : null);
    private final ByteArray bytes = (ByteArray) Proxy.newProxyInstance(getClass().getClassLoader(),
            new Class<?>[]{ByteArray.class}, (p, m, a) -> m.getName().equals("hashCode") ? 3
                    : m.getName().equals("equals") ? p == a[0] : null);

    @BeforeEach
    void install() {
        saved = ObjectFactoryLocator.FACTORY;
        ObjectFactoryLocator.FACTORY = (MontoyaObjectFactory) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{MontoyaObjectFactory.class}, (p, m, a) -> {
                    calls.add(new Object[]{m.getName(), a});
                    switch (m.getName()) {
                        case "httpService": return service;
                        case "byteArray": return bytes;
                        case "httpRequest": return request;
                        default: return null;
                    }
                });
    }

    @AfterEach
    void restore() {
        ObjectFactoryLocator.FACTORY = saved;
    }

    private MontoyaApi api(List<Object[]> repeaterCalls) {
        Repeater repeater = (Repeater) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{Repeater.class}, (p, m, a) -> {
                    repeaterCalls.add(new Object[]{m.getName(), a});
                    return null;
                });
        return (MontoyaApi) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{MontoyaApi.class},
                (p, m, a) -> m.getName().equals("repeater") ? repeater : null);
    }

    @Test
    void buildsServiceAndRequestAndSends() {
        byte[] raw = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nÿ".getBytes(StandardCharsets.ISO_8859_1);
        BuiltRequest br = new BuiltRequest("example.com", 8443, true, raw, "GET", "https://example.com:8443/", List.of());
        List<Object[]> rc = new ArrayList<>();
        new MontoyaRequestSink(api(rc)).send(br, null);

        Object[] svc = calls.stream().filter(c -> c[0].equals("httpService")).findFirst().orElseThrow();
        assertArrayEquals(new Object[]{"example.com", 8443, true}, (Object[]) svc[1]);
        Object[] ba = calls.stream().filter(c -> c[0].equals("byteArray")).findFirst().orElseThrow();
        assertArrayEquals(raw, (byte[]) ((Object[]) ba[1])[0]);
        Object[] req = calls.stream().filter(c -> c[0].equals("httpRequest")).findFirst().orElseThrow();
        assertSame(service, ((Object[]) req[1])[0]);
        assertSame(bytes, ((Object[]) req[1])[1]);

        assertEquals(1, rc.size());
        assertEquals("sendToRepeater", rc.get(0)[0]);
        assertEquals(1, ((Object[]) rc.get(0)[1]).length);
        assertSame(request, ((Object[]) rc.get(0)[1])[0]);
    }

    @Test
    void namedTabPassesName() {
        BuiltRequest br = new BuiltRequest("h", 80, false, new byte[]{1}, "GET", "http://h/", List.of());
        List<Object[]> rc = new ArrayList<>();
        new MontoyaRequestSink(api(rc)).send(br, "curl 2/3");
        assertEquals(2, ((Object[]) rc.get(0)[1]).length);
        assertEquals("curl 2/3", ((Object[]) rc.get(0)[1])[1]);
    }
}

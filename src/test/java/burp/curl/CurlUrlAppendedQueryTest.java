package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * Appended query text ({@code -G} data) as the real curl 8.7.1 sends it. Captured with a one-connection capture
 * server on 127.0.0.1 and {@code curl -G -d <piece> http://127.0.0.1:PORT/x}.
 */
class CurlUrlAppendedQueryTest {
    private static String target(String url, String piece) throws Exception {
        return CurlUrl.parse(url, null, false).withAppendedQuery(piece).requestTarget();
    }

    @Test
    void hexDigitsOfValidEscapesAreLowerCased() throws Exception {
        // curl -G -d 'a=%4A' 'http://h/x?q=%4A'  ->  GET /x?q=%4A&a=%4a   (the URL's own query keeps its case)
        assertEquals("/x?q=%4A&a=%4a", target("http://h/x?q=%4A", "a=%4A"));
        // curl -G -d 'a=%00%7E' -> /x?a=%00%7e
        assertEquals("/x?a=%00%7e", target("http://h/x", "a=%00%7E"));
        // curl -G -d 'a=%zz%4A%' -> /x?a=%zz%4a%   (invalid escapes stay)
        assertEquals("/x?a=%zz%4a%", target("http://h/x", "a=%zz%4A%"));
        // curl -G -d 'c=%2F%c3%A9' -> /x?c=%2f%c3%a9
        assertEquals("/x?c=%2f%c3%a9", target("http://h/x", "c=%2F%c3%A9"));
    }

    @Test
    void fragmentOfTheAppendedTextIsDropped() throws Exception {
        // curl -G -d 'a=b#c' http://h/x -> /x?a=b
        assertEquals("/x?a=b", target("http://h/x", "a=b#c"));
    }

    @Test
    void otherCharactersPassThrough() throws Exception {
        // curl -G -d 'a=+=&~-._[]' -> /x?a=+=&~-._[]
        assertEquals("/x?a=+=&~-._[]", target("http://h/x", "a=+=&~-._[]"));
    }
}

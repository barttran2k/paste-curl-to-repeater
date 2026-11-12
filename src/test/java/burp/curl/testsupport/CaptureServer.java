package burp.curl.testsupport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Minimal loopback HTTP/1.1 server that records the raw bytes of every request it receives and answers each with
 * {@code 200 OK} and an empty body. Handles keep-alive, several connections, {@code Content-Length} and chunked
 * bodies (the chunk framing is kept in the capture) and {@code Expect: 100-continue}. Binds 127.0.0.1 and, when the
 * machine has an IPv6 loopback, ::1 on the same port.
 */
public final class CaptureServer implements AutoCloseable {
    private static final byte[] OK = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CONTINUE = "HTTP/1.1 100 Continue\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
    private static final Pattern REQUEST_LINE = Pattern.compile("^[A-Za-z]+ [^ ]* HTTP/1\\.[01]\r\n.*", Pattern.DOTALL);
    private static final int READ_TIMEOUT_MS = 10_000;

    private static Boolean ipv6Cached;

    private final List<ServerSocket> listeners = new ArrayList<>();
    private final List<Socket> sockets = Collections.synchronizedList(new ArrayList<>());
    private final List<Thread> threads = Collections.synchronizedList(new ArrayList<>());
    private final List<byte[]> requests = Collections.synchronizedList(new ArrayList<>());
    private final int port;
    private volatile boolean closed;

    private CaptureServer(int port) {
        this.port = port;
    }

    /** @return true when ::1 can be bound on this machine */
    public static synchronized boolean ipv6LoopbackAvailable() {
        if (ipv6Cached == null) {
            try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getByName("::1"))) {
                ipv6Cached = s.isBound();
            } catch (IOException e) {
                ipv6Cached = false;
            }
        }
        return ipv6Cached;
    }

    /**
     * Starts a server on an ephemeral port.
     * @return the running server
     * @throws IOException if no port can be bound
     */
    public static CaptureServer start() throws IOException {
        boolean v6 = ipv6LoopbackAvailable();
        IOException last = null;
        for (int attempt = 0; attempt < 30; attempt++) {
            ServerSocket s4 = new ServerSocket(0, 64, InetAddress.getByName("127.0.0.1"));
            ServerSocket s6 = null;
            if (v6) {
                try {
                    s6 = new ServerSocket(s4.getLocalPort(), 64, InetAddress.getByName("::1"));
                } catch (IOException e) {
                    last = e;
                    s4.close();
                    continue;
                }
            }
            CaptureServer srv = new CaptureServer(s4.getLocalPort());
            srv.listen(s4);
            if (s6 != null) {
                srv.listen(s6);
            }
            return srv;
        }
        throw new IOException("cannot bind 127.0.0.1 and ::1 on the same port", last);
    }

    /** @return the port both loopback addresses listen on */
    public int port() {
        return port;
    }

    /** @return true when ::1 is bound too */
    public boolean ipv6() {
        return listeners.size() > 1;
    }

    /** @return the captured requests in completion order (copy); call after {@link #close()} for a stable view */
    public List<byte[]> requests() {
        synchronized (requests) {
            return new ArrayList<>(requests);
        }
    }

    private void listen(ServerSocket ss) {
        listeners.add(ss);
        Thread t = new Thread(() -> {
            while (!closed) {
                try {
                    Socket s = ss.accept();
                    sockets.add(s);
                    Thread h = new Thread(() -> handle(s), "capture-conn");
                    h.setDaemon(true);
                    threads.add(h);
                    h.start();
                } catch (IOException e) {
                    return;
                }
            }
        }, "capture-accept");
        t.setDaemon(true);
        t.start();
    }

    /** Growable byte buffer fed from a socket. */
    private static final class Buf {
        byte[] data = new byte[8192];
        int len;
        final InputStream in;

        Buf(InputStream in) {
            this.in = in;
        }

        /** @return false on EOF or timeout */
        boolean fill() {
            if (len == data.length) {
                data = Arrays.copyOf(data, data.length * 2);
            }
            try {
                int n = in.read(data, len, data.length - len);
                if (n < 0) {
                    return false;
                }
                len += n;
                return true;
            } catch (IOException e) {
                return false;
            }
        }

        int indexOf(byte[] needle, int from) {
            outer:
            for (int i = Math.max(from, 0); i <= len - needle.length; i++) {
                for (int j = 0; j < needle.length; j++) {
                    if (data[i + j] != needle[j]) {
                        continue outer;
                    }
                }
                return i;
            }
            return -1;
        }

        byte[] take(int n) {
            byte[] r = Arrays.copyOf(data, n);
            System.arraycopy(data, n, data, 0, len - n);
            len -= n;
            return r;
        }
    }

    private static final byte[] CRLF2 = {'\r', '\n', '\r', '\n'};
    private static final byte[] CRLF = {'\r', '\n'};

    private void handle(Socket s) {
        try (s) {
            s.setSoTimeout(READ_TIMEOUT_MS);
            Buf buf = new Buf(s.getInputStream());
            OutputStream out = s.getOutputStream();
            int myLast = -1; // index in requests of the last request of this connection
            while (true) {
                int headEnd;
                int from = 0;
                while ((headEnd = buf.indexOf(CRLF2, from)) < 0) {
                    from = Math.max(0, buf.len - 3);
                    if (!buf.fill()) {
                        if (buf.len > 0) {
                            record(buf.take(buf.len));
                        }
                        return;
                    }
                }
                headEnd += 4;
                String head = new String(buf.data, 0, headEnd, StandardCharsets.ISO_8859_1);
                if (myLast >= 0 && !REQUEST_LINE.matcher(head).matches()) {
                    // not a request line: stray body bytes of the previous request, keep them with it
                    appendTo(myLast, buf.take(headEnd));
                    continue;
                }
                long contentLength = 0;
                boolean chunked = false;
                boolean expect = false;
                for (String line : head.split("\r\n")) {
                    int c = line.indexOf(':');
                    if (c <= 0) {
                        continue;
                    }
                    String name = line.substring(0, c).trim().toLowerCase();
                    String value = line.substring(c + 1).trim();
                    switch (name) {
                        case "content-length" -> {
                            try {
                                contentLength = Long.parseLong(value);
                            } catch (NumberFormatException e) {
                                contentLength = 0;
                            }
                        }
                        case "transfer-encoding" -> chunked |= value.toLowerCase().contains("chunked");
                        case "expect" -> expect |= value.equalsIgnoreCase("100-continue");
                        default -> { }
                    }
                }
                boolean hasBody = chunked || contentLength > 0;
                if (expect && hasBody) {
                    out.write(CONTINUE);
                    out.flush();
                }
                int end;
                if (chunked) {
                    end = readChunked(buf, headEnd);
                } else {
                    long total = headEnd + contentLength;
                    while (buf.len < total) {
                        if (!buf.fill()) {
                            break;
                        }
                    }
                    end = (int) Math.min(total, buf.len);
                }
                if (end < 0) {
                    record(buf.take(buf.len));
                    return;
                }
                myLast = record(buf.take(end));
                out.write(OK);
                out.flush();
            }
        } catch (IOException e) {
            // connection dropped
        }
    }

    /** @return index just past the final chunk and trailers, or -1 if the stream ended early */
    private static int readChunked(Buf buf, int pos) {
        while (true) {
            int eol;
            while ((eol = buf.indexOf(CRLF, pos)) < 0) {
                if (!buf.fill()) {
                    return -1;
                }
            }
            String sizeLine = new String(buf.data, pos, eol - pos, StandardCharsets.ISO_8859_1);
            int semi = sizeLine.indexOf(';');
            String hex = (semi >= 0 ? sizeLine.substring(0, semi) : sizeLine).trim();
            long size;
            try {
                size = Long.parseLong(hex, 16);
            } catch (NumberFormatException e) {
                return buf.len;
            }
            pos = eol + 2;
            if (size == 0) {
                // trailers until an empty line
                while (true) {
                    int e2;
                    while ((e2 = buf.indexOf(CRLF, pos)) < 0) {
                        if (!buf.fill()) {
                            return -1;
                        }
                    }
                    boolean empty = e2 == pos;
                    pos = e2 + 2;
                    if (empty) {
                        return pos;
                    }
                }
            }
            long need = pos + size + 2;
            while (buf.len < need) {
                if (!buf.fill()) {
                    return -1;
                }
            }
            pos = (int) need;
        }
    }

    private int record(byte[] raw) {
        synchronized (requests) {
            requests.add(raw);
            return requests.size() - 1;
        }
    }

    private void appendTo(int index, byte[] more) {
        synchronized (requests) {
            byte[] old = requests.get(index);
            byte[] merged = Arrays.copyOf(old, old.length + more.length);
            System.arraycopy(more, 0, merged, old.length, more.length);
            requests.set(index, merged);
        }
    }

    /** Stops listening, drops connections and waits briefly for handlers so {@link #requests()} is stable. */
    @Override
    public void close() {
        closed = true;
        for (ServerSocket l : listeners) {
            try {
                l.close();
            } catch (IOException e) {
                // ignore
            }
        }
        List<Thread> hs;
        synchronized (threads) {
            hs = new ArrayList<>(threads);
        }
        for (Thread t : hs) {
            try {
                t.join(300);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        synchronized (sockets) {
            for (Socket s : sockets) {
                try {
                    s.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
        for (Thread t : hs) {
            try {
                t.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    /** Convenience for tests. */
    public static String text(byte[] raw) {
        return new String(raw, StandardCharsets.ISO_8859_1);
    }
}

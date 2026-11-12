package burp.curl;

import java.time.DateTimeException;
import java.time.LocalDate;
import java.util.Locale;
import java.util.Map;

/**
 * A port of the date parsing of curl 8.7.1 ({@code curl_getdate}, used by {@code -z} and by cookie expiry) and of
 * its RFC 1123 output. Weekday names are ignored, months are the English three-letter names, time zones the
 * names of curl's table or a {@code +hhmm}/{@code -hhmm} offset up to 1400.
 */
final class CurlDate {
    private static final String[] WEEKDAYS = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};
    private static final String[] WEEKDAYS_LONG =
            {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"};
    private static final String[] MONTHS =
            {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    /** minutes to add to the written time to get GMT */
    private static final Map<String, Integer> ZONES = Map.ofEntries(
            Map.entry("GMT", 0), Map.entry("UT", 0), Map.entry("UTC", 0), Map.entry("WET", 0),
            Map.entry("BST", -60), Map.entry("WAT", 60), Map.entry("AST", 240), Map.entry("ADT", 180),
            Map.entry("EST", 300), Map.entry("EDT", 240), Map.entry("CST", 360), Map.entry("CDT", 300),
            Map.entry("MST", 420), Map.entry("MDT", 360), Map.entry("PST", 480), Map.entry("PDT", 420),
            Map.entry("YST", 540), Map.entry("YDT", 480), Map.entry("HST", 600), Map.entry("HDT", 540),
            Map.entry("CAT", 600), Map.entry("AHST", 600), Map.entry("NT", 660), Map.entry("IDLW", 720),
            Map.entry("CET", -60), Map.entry("MET", -60), Map.entry("MEWT", -60), Map.entry("MEST", -120),
            Map.entry("CEST", -120), Map.entry("MESZ", -120), Map.entry("FWT", -60), Map.entry("FST", -120),
            Map.entry("EET", -120), Map.entry("WAST", -420), Map.entry("WADT", -420), Map.entry("CCT", -480),
            Map.entry("JST", -540), Map.entry("EAST", -600), Map.entry("EADT", -600), Map.entry("GST", -600),
            Map.entry("NZT", -720), Map.entry("NZST", -720), Map.entry("NZDT", -780), Map.entry("IDLE", -720));

    private CurlDate() {
    }

    private static boolean alpha(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }

    private static boolean digit(char c) {
        return c >= '0' && c <= '9';
    }

    private static int checkDay(String w) {
        for (int i = 0; i < 7; i++) {
            if (w.length() == 3 ? w.equalsIgnoreCase(WEEKDAYS[i]) : w.equalsIgnoreCase(WEEKDAYS_LONG[i])) {
                return i;
            }
        }
        return -1;
    }

    private static int checkMonth(String w) {
        for (int i = 0; i < 12; i++) {
            if (w.equalsIgnoreCase(MONTHS[i])) {
                return i;
            }
        }
        return -1;
    }

    /** @return minutes to add to get GMT, or null when the word is not a time zone */
    private static Integer checkZone(String w) {
        String u = w.toUpperCase(Locale.ROOT);
        Integer z = ZONES.get(u);
        if (z != null) {
            return z;
        }
        if (u.length() == 1) {
            char c = u.charAt(0);
            if (c == 'Z') {
                return 0;
            }
            if (c >= 'A' && c <= 'I') {
                return 60 * (c - 'A' + 1);
            }
            if (c >= 'K' && c <= 'M') {
                return 60 * (c - 'K' + 10);
            }
            if (c >= 'N' && c <= 'Y') {
                return -60 * (c - 'N' + 1);
            }
        }
        return null;
    }

    /**
     * @param date the text
     * @return seconds since the epoch, or null when curl cannot parse it
     */
    static Long parse(String date) {
        int wday = -1;
        int mon = -1;
        int mday = -1;
        int hour = -1;
        int min = -1;
        int sec = -1;
        int year = -1;
        Integer tz = null;
        boolean nextIsMday = true;
        int part = 0;
        int p = 0;
        int n = date.length();
        while (p < n && part < 6) {
            boolean found = false;
            while (p < n && !(alpha(date.charAt(p)) || digit(date.charAt(p)))) {
                p++;
            }
            if (p >= n) {
                break;
            }
            char c = date.charAt(p);
            if (alpha(c)) {
                int e = p;
                while (e < n && alpha(date.charAt(e))) {
                    e++;
                }
                String w = date.substring(p, e);
                if (wday == -1) {
                    wday = checkDay(w);
                    found = wday != -1;
                }
                if (!found && mon == -1) {
                    mon = checkMonth(w);
                    found = mon != -1;
                }
                if (!found && tz == null) {
                    tz = checkZone(w);
                    found = tz != null;
                }
                if (!found) {
                    return null;
                }
                p = e;
            } else {
                int[] t = sec == -1 ? time(date, p) : null;
                if (t != null) {
                    hour = t[0];
                    min = t[1];
                    sec = t[2];
                    p = t[3];
                } else {
                    int e = p;
                    while (e < n && digit(date.charAt(e))) {
                        e++;
                    }
                    if (e - p > 9) {
                        return null;
                    }
                    int val = Integer.parseInt(date.substring(p, e));
                    int len = e - p;
                    if (tz == null && len == 4 && val <= 1400 && p > 0
                            && (date.charAt(p - 1) == '+' || date.charAt(p - 1) == '-')) {
                        found = true;
                        int off = val / 100 * 60 + val % 100;
                        tz = date.charAt(p - 1) == '+' ? -off : off;
                    }
                    if (len == 8 && year == -1 && mon == -1 && mday == -1) {
                        found = true;
                        year = val / 10000;
                        mon = (val % 10000) / 100 - 1;
                        mday = val % 100;
                    }
                    if (!found && nextIsMday && mday == -1) {
                        if (val > 0 && val < 32) {
                            mday = val;
                            found = true;
                        }
                        nextIsMday = false;
                    }
                    if (!found && !nextIsMday && year == -1) {
                        year = val;
                        found = true;
                        if (year < 100) {
                            year += year > 70 ? 1900 : 2000;
                        } else if (year < 1583) {
                            return null; // measured: curl 8.7.1 rejects the years 100 to 1582
                        }
                        if (mday == -1) {
                            nextIsMday = true;
                        }
                    }
                    if (!found) {
                        return null;
                    }
                    p = e;
                }
            }
            part++;
        }
        if (sec == -1) {
            sec = 0;
            min = 0;
            hour = 0;
        }
        if (mday == -1 || mon == -1 || year == -1) {
            return null;
        }
        if (mon < 0 || mon > 11 || hour > 23 || min > 59 || sec > 60 || mday > 31) {
            return null;
        }
        try {
            long days = LocalDate.of(year, 1, 1).plusMonths(mon).plusDays(mday - 1L).toEpochDay();
            long t = days * 86400L + hour * 3600L + min * 60L + sec;
            return t + (tz == null ? 0 : tz) * 60L;
        } catch (DateTimeException e) {
            return null;
        }
    }

    /** {@code hh:mm:ss} or {@code hh:mm} (up to two digits each) at {@code p}; {hour, min, sec, next} or null. */
    private static int[] time(String s, int p) {
        int[] h = twoDigits(s, p);
        if (h == null || h[1] >= s.length() || s.charAt(h[1]) != ':') {
            return null;
        }
        int[] m = twoDigits(s, h[1] + 1);
        if (m == null) {
            return null;
        }
        if (m[1] < s.length() && s.charAt(m[1]) == ':') {
            int[] sec = twoDigits(s, m[1] + 1);
            if (sec != null) {
                return new int[] {h[0], m[0], sec[0], sec[1]};
            }
        }
        return new int[] {h[0], m[0], 0, m[1]};
    }

    /** @return {value, next} of up to two digits at {@code p}, or null */
    private static int[] twoDigits(String s, int p) {
        int e = p;
        while (e < s.length() && e - p < 2 && digit(s.charAt(e))) {
            e++;
        }
        return e == p ? null : new int[] {Integer.parseInt(s.substring(p, e)), e};
    }

    /** @return {@code Sun, 06 Nov 1994 08:49:37 GMT} */
    static String format(long epoch) {
        long days = Math.floorDiv(epoch, 86400L);
        int secs = (int) Math.floorMod(epoch, 86400L);
        LocalDate d = LocalDate.ofEpochDay(days);
        return String.format("%s, %02d %s %4d %02d:%02d:%02d GMT", WEEKDAYS[d.getDayOfWeek().getValue() - 1],
                d.getDayOfMonth(), MONTHS[d.getMonthValue() - 1], d.getYear(), secs / 3600, secs / 60 % 60,
                secs % 60);
    }
}

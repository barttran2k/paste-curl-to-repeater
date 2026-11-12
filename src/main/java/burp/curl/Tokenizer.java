package burp.curl;

/** Splits pasted shell text into simple commands of words. Executes nothing. */
public interface Tokenizer {
    /**
     * @param input the pasted text
     * @return the commands and warnings
     * @throws CurlParseException if the text cannot be tokenized (e.g. unterminated quote)
     */
    TokenizeResult tokenize(String input) throws CurlParseException;
}

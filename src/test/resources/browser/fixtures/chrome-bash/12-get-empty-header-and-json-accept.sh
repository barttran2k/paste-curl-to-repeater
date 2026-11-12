curl --url 'http://__HOSTPORT__/api/v2/me' \
  -H 'accept: application/json' \
  -H 'authorization: Bearer FAKE_JWT_FOR_TESTS' \
  -H 'if-none-match: W/"33a64df551425fcc55e4d42a148795d9f25f89d4"' \
  -H 'x-empty;' \
  -H 'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
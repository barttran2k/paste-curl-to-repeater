curl 'http://__HOSTPORT__/api/v2/users/42' \
-X 'OPTIONS' \
-H 'Accept: */*' \
-H 'Access-Control-Request-Headers: authorization, content-type' \
-H 'Access-Control-Request-Method: PUT' \
-H 'Origin: http://app.example.test' \
-H 'Referer: http://app.example.test/' \
-H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15' \
-H 'Host: __HOSTPORT__'
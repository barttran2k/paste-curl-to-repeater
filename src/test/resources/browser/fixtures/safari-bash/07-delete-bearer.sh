curl 'http://__HOSTPORT__/api/v2/items/7' \
-X 'DELETE' \
-H 'Accept: application/json, text/plain, */*' \
-H 'Accept-Language: en-US,en;q=0.9' \
-H 'Origin: http://__HOSTPORT__' \
-H 'Referer: http://__HOSTPORT__/app/users/42' \
-H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15' \
-H 'Cookie: session=fake-session-id; csrftoken=fake-csrf-token' \
-H 'Host: __HOSTPORT__' \
-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlLXVzZXIifQ.ZmFrZS1zaWduYXR1cmU'
curl.exe ^"http://__HOSTPORT__/api/upload^" ^
  -X POST ^
  -H ^"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0^" ^
  -H ^"Accept: application/json, text/plain, */*^" ^
  -H ^"Accept-Language: en-US,en;q=0.5^" ^
  -H ^"Accept-Encoding: gzip, deflate, br, zstd^" ^
  -H ^"Origin: http://__HOSTPORT__^" ^
  -H ^"Connection: keep-alive^" ^
  -H ^"Referer: http://__HOSTPORT__/app/upload^" ^
  -H ^"Cookie: session=fake-session-id; csrftoken=fake-csrf-token^" ^
  -H ^"Sec-Fetch-Dest: empty^" ^
  -H ^"Sec-Fetch-Mode: cors^" ^
  -H ^"Sec-Fetch-Site: same-origin^" ^
  -H ^"Priority: u=0^" ^
  -H ^"Content-Type: multipart/form-data; boundary=----geckoformboundary4c7e91ab2d3f50168e9a7b6c5d4e3f21^" ^
  --data-binary ^
  ^"------geckoformboundary4c7e91ab2d3f50168e9a7b6c5d4e3f21^

Content-Disposition: form-data; name=^\^"title^\^"^

^

Quarterly report^

------geckoformboundary4c7e91ab2d3f50168e9a7b6c5d4e3f21^

Content-Disposition: form-data; name=^\^"file^\^"; filename=^\^"report.bin^\^"^

Content-Type: application/octet-stream^

^

------geckoformboundary4c7e91ab2d3f50168e9a7b6c5d4e3f21--^

^"
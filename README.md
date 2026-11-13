# cachepoison

A cache-store admission tool. It has to build a canonical cache key and refuse to store responses that would be poisoned by unkeyed inputs, method override, fat GET, header splitting, or Set-Cookie.

`python -m cachepoison inspect --request fixtures/requests/ok-get.raw --response fixtures/responses/ok-get.raw` already parses both messages. `process` is still a stub.

Standard library only. No Docker, no HTTP cache daemons.

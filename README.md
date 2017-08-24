# init-redis
python script that walks over given hostnames and initialize redis with sentinel.

THIS IS ONLY for self purpose, has not been tested properly!


## usage
```
usage: init-redis.py [-h] --servers SERVER [SERVER ...] --quorum QUORUM
                     [--sentinels SENTINEL [SENTINEL ...]]
                     [--groupmaster NAME] [-v]

optional arguments:
  -h, --help            show this help message and exit
  --sentinels SENTINEL [SENTINEL ...]
  --groupmaster NAME    master group name
  -v                    verbosity (repeat for more verbose log)

required arguments:
  --servers SERVER [SERVER ...]
  --quorum QUORUM
```

## description

Redis sentinel architecture is wierd, do not use redis sentinel if not necessary.

Give the script hostnames with optional port number.
From servers, the first will be elected master and the rest are slaves.
Sentinels are configured to monitor master with name defined using --groupmaster and defined quorum.

## Redis docs
Read the redis documentation for more info
 * https://redis.io/topics/sentinel
 * https://redis.io/topics/replication

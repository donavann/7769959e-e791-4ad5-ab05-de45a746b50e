key1=$(curl --silent --data "password=fubar" http://localhost:8888/hash)
echo ${key1}

sleep 6   # This will let key1 become available

key2=$(curl --silent --data "password=fubar" http://localhost:8888/hash)
echo ${key2}

res=$(curl -s http://localhost:8888/shutdown)
echo ${res}

res=$(curl -s --data "password=hubar" http://localhost:8888/hash)
echo ${res}

token1=$(curl --silent http://localhost:8888/hash/${key1})
token2=$(curl --silent http://localhost:8888/hash/${key2})

echo ${token1}
echo ${token2}

stats=$(curl --silent http://localhost:8888/stats)
echo ${stats}

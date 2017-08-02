echo "keys"  

key1=$(curl --silent --data "password=fubar" http://localhost:8888/hash)
echo ${key1}

key_list="${key1}"

key2=$(curl --silent --data "password=correctbatteryhorsestaple" http://localhost:8888/hash)
echo ${key2}
key_list="${key_list} ${key2}"

key3=$(curl --silent --data "password=incorrectbatteryhorsestaple" http://localhost:8888/hash)
echo ${key3}
key_list="${key_list} ${key3}"

echo "sleeping"
sleep 6   # let key values become available

for key in ${key_list}
do
   value="$(curl --silent http://localhost:8888/hash/${key})"
   echo "${key}: ${value}"
done

echo ""
echo "Statistics"
echo "$(curl --silent http://localhost:8888/stats)"

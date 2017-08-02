

rm -f keys.txt serial.reads parallel.reads sr pr

echo "Submitting hash requests"

for i in {1..100}
do
   curl --silent --data "password=${i}" http://localhost:8888/hash >> keys.txt &
done

echo "sleeping"
sleep 6

while read key
do
   # parallel reads
   curl --silent http://localhost:8888/hash/${key} >> parallel.reads &
done < keys.txt

while read key
do
   # serial reads
   value="$(curl --silent http://localhost:8888/hash/${key})"
   echo "${key}: ${value}"
   echo "${value}" >> serial.reads
done < keys.txt

echo "sleeping"
sleep 5

sort serial.reads > sr
sort parallel.reads > pr
echo "Differences; serial vs parallel reads:"
diff sr pr

echo ""
echo "Statistics"
echo "$(curl --silent http://localhost:8888/stats)"


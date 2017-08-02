
#unsupported method 
error1=$( curl --silent -T $0 http://localhost:8888/hash/333 )
echo ${error1}

# post to unknown URL
error2=$( curl --silent --data "foo=bar" http://localhost:8888/hasher )
echo ${error2}

# get to unknown URL
error3=$( curl --silent http://localhost:8888/hash/3iea )
echo ${error3}

# get to unknown URL
error4=$( curl --silent http://localhost:8888/hash/777777777777777777 )
echo ${error4}

# bad post data
error4=$( curl --silent --data "foo=bar" http://localhost:8888/hash )
echo ${error4}




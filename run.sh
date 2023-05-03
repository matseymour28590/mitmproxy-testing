#!/bin/bash
images=$(docker image list)
matches=$(echo "$images" |grep mitmproxy-testing)
run=true
if [ "$1" == "--build" ] || [ "$matches" == "" ]; then
  run=false
  docker build -t mitmproxy-testing . && run=true
fi
if [ $run == true ]; then
  docker run --cap-add NET_ADMIN -v ./testing:/code/testing mitmproxy-testing sh -c 'nginx && python /code/testing/test_accuracy.py'
fi

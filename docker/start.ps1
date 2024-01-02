docker stop $(docker ps -a -q)
docker rm --force --volumes $(docker ps -a -q)
docker rmi pyvoip/tests
docker build . -t pyvoip/tests
docker run --add-host host.docker.internal:host-gateway -d -p 5060:5060/udp -p 5061-5062:5061-5062/tcp pyvoip/tests

@echo off
docker rmi pyvoip/tests
docker build . -t pyvoip/tests
docker run -d -p 5060:5060/udp -p 5061-5062:5061-5062/tcp pyvoip/tests

build dff inside docker :
-------------------------

docker build --force-rm -t dff2:latest . #build docker (repos dff2 tag latest use curent Dockerfile)

run dff from docker  :
----------------------

docker run --net=host --env="DISPLAY" --volume="$HOME/.Xauthority:/root/.Xauthority:rw" -it dff2:latest -v ~/dump:/mnt/dump 


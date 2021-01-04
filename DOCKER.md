
get the docker image from the docker repository :
-------------------------------------------------

docker pull solaljacob/dff2

build dff inside docker :
-------------------------

docker build --force-rm -t dff2:latest .

load a prebuilt DFF docker image :
----------------------------------

bzcat dff-docker-images.tar.bz2 | docker load

run dff from docker  :
----------------------

docker run --net=host --env="DISPLAY" --volume="$HOME/.Xauthority:/root/.Xauthority:rw" -v ~/dump:/root/dump -it dff2:latest

(This will share your /home/user/dump directory inside docker /root/dump directory)

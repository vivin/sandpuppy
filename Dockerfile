FROM ubuntu:20.04
ARG UNAME=vivin
ARG UID=1000
ARG GID=1000
RUN dpkg --add-architecture i386 && apt-get update && env DEBIAN_FRONTEND="noninteractive" TZ="America/Phoenix" apt-get -y install sudo curl parallel rsync ssh libc6-i386 lib32stdc++6 lib32gcc1 lib32ncurses6 lib32z1 libsdl2-2.0 libsdl2-2.0:i386 libc6:i386 libncurses6:i386 libstdc++6:i386 libbz2-dev libbz2-dev:i386 libpython3.8
RUN groupadd -g $GID -o $UNAME && useradd -m -u $UID -g $GID -o -s /bin/bash $UNAME && echo "$UNAME:$UNAME" | chpasswd && adduser $UNAME sudo && echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
COPY resources/docker/container_bashrc /home/vivin/.bashrc
COPY tools/FuzzFactory /home/vivin/Projects/phd/tools/FuzzFactory
COPY tools/aflplusplus /home/vivin/Projects/phd/tools/aflplusplus
COPY resources/seeds /home/vivin/Projects/phd/resources/seeds
COPY ["resources/docker/Super Mario Bros. (JU) (PRG0) [[]!].nes", "/home/vivin/Projects/phd/"]
RUN chown -R $UNAME:$UNAME /home/vivin
USER $UNAME
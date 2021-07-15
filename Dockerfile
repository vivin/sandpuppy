FROM ubuntu:20.04
ARG UNAME=vivin
ARG UID=1000
ARG GID=1000
RUN dpkg --add-architecture i386 && apt-get update && apt-get -y install sudo curl libc6-i386 lib32stdc++6 lib32gcc1 lib32ncurses6 lib32z1 libsdl2-2.0 libsdl2-2.0:i386 libc6:i386 libncurses6:i386 libstdc++6:i386
RUN groupadd -g $GID -o $UNAME && useradd -m -u $UID -g $GID -o -s /bin/bash $UNAME && echo "$UNAME:$UNAME" | chpasswd && adduser $UNAME sudo && echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
COPY tools/FuzzFactory /home/vivin/Projects/phd/tools/FuzzFactory
COPY resources/seeds /home/vivin/Projects/phd/resources/seeds
COPY ["Super Mario Bros. (JU) (PRG0) [[]!].nes", "/home/vivin/Projects/phd/"]
RUN chown -R $UNAME:$UNAME /home/vivin
USER $UNAME
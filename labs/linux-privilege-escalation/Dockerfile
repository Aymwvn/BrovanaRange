FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y --no-install-recommends sudo vim nano curl iproute2 procps && apt clean && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash student && echo 'student:student' | chpasswd
RUN echo 'student ALL=(ALL) NOPASSWD: /usr/bin/vim' > /etc/sudoers.d/linux-privilege-escalation && chmod 440 /etc/sudoers.d/linux-privilege-escalation
RUN mkdir -p /home/student/notes && echo 'Hint: check sudo permissions with sudo -l' > /home/student/notes/readme.txt && chown -R student:student /home/student/notes
RUN echo 'REDRANGE{placeholder_dynamic_flag}' > /root/flag.txt && chmod 600 /root/flag.txt && chown root:root /root/flag.txt
WORKDIR /home/student
CMD ["/bin/bash", "-lc", "sleep infinity"]

FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y --no-install-recommends sudo file findutils grep vim nano procps && apt clean && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash student && echo 'student:student' | chpasswd && echo 'student ALL=(ALL) NOPASSWD: /usr/bin/find' > /etc/sudoers.d/forensic-skeleton && chmod 440 /etc/sudoers.d/forensic-skeleton
RUN mkdir -p /home/student/evidence /var/log/redrange /opt/.cache
RUN echo 'Suspicious login from 10.10.14.9 at 03:14' > /var/log/redrange/auth.log
RUN echo 'The attacker hid something under /opt/.cache' > /home/student/evidence/incident_note.txt
RUN echo 'REDRANGE{placeholder_dynamic_flag}' > /root/flag.txt && chmod 600 /root/flag.txt
RUN echo 'Hint: investigate /var/log/redrange and hidden directories.' > /home/student/README.txt && chown -R student:student /home/student
WORKDIR /home/student
CMD ["/bin/bash", "-lc", "sleep infinity"]

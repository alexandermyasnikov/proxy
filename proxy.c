
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>

////////////////////////////////////////////////////////////////////////////////

void print_hex(void* buf, int len) {
  printf("hex: {");
  for (int i = 0; i < len; ++i) {
    printf("%x ", *(i + (uint8_t*) buf));
  }
  printf("} %d \n", len);
}

////////////////////////////////////////////////////////////////////////////////

struct proxy_rule_t {
  int     port_src;
  char*   ip_src;
  int     port_dst;
  char*   ip_dst;
};

////////////////////////////////////////////////////////////////////////////////

struct proxy_t {
  struct proxy_rule_t _rule;
};

int proxy_start(struct proxy_t* proxy);
int proxy_stop(struct proxy_t* proxy);
int proxy_add_rule(struct proxy_t* proxy, struct proxy_rule_t* rule);
int proxy_set_nonblock(int fd);

////////////////////////////////////////////////////////////////////////////////

int proxy_start(struct proxy_t* proxy) {
  int ret;
  int sockfd;
  {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    printf("sockfd: %d \n", sockfd);
    if (sockfd == -1) {
      return -1;
    }

    int on = 1;
    ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    printf("setsockopt(...): %d \n", ret);
    if (ret == -1) {
      return -1;
    }

    struct in_addr ip_src = {0};
    ret = inet_pton(AF_INET, proxy->_rule.ip_src, &ip_src);
    printf("inet_pton(...): %d \n", ret);
    if (ret == -1) {
      return -1;
    }

    struct sockaddr_in addr;
    memset((char *) &addr, 0, sizeof(addr));
    addr.sin_family      = PF_INET;
    addr.sin_addr.s_addr = ip_src.s_addr;
    addr.sin_port        = htons(proxy->_rule.port_src);

    ret = bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));
    printf("bind(...): %d \n", ret);
    if (ret == -1) {
      return -1;
    }

    ret = proxy_set_nonblock(sockfd);
    printf("proxy_set_nonblock(...): %d \n", ret);
    if (ret == -1) {
      return -1;
    }

    ret = listen(sockfd, SOMAXCONN);
    printf("listen(...): %d \n", ret);
    if (ret == -1) {
      return -1;
    }
  }

  int epfd = epoll_create1(0);
  printf("epfd: %d \n", epfd);

  const int MAX_EVENTS = 10;
  struct epoll_event events[MAX_EVENTS];

  struct epoll_event event;
  event.data.fd = sockfd;
  event.events = EPOLLIN;

  ret = epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &event);

  int BUFFER_LEN = 1024;
  uint8_t buffer[BUFFER_LEN];

  while (1) {
    int event_count = epoll_wait(epfd, events, MAX_EVENTS, -1);
    // printf("event_count: %d \n", event_count);

    for (int i = 0; i < event_count; i++) {
      printf("events 0x%x \n", events[i].events);
      if ((events[i].events & EPOLLERR) ||
          (events[i].events & EPOLLHUP) ||
          (!(events[i].events & EPOLLIN)))
      {
        printf("epoll error \n");
        close(events[i].data.fd);

      } else if (events[i].data.fd == sockfd) {
        int infd;
        infd = accept(sockfd, 0, 0);
        printf("infd: %d \n", infd);
        if (infd == -1) {
          break;
        }

        ret = proxy_set_nonblock(infd);
        printf("proxy_set_nonblock(...): %d \n", ret);
        if (ret == -1) {
          return -1;
        }

        event.data.fd = infd;
        event.events = EPOLLIN;
        ret = epoll_ctl(epfd, EPOLL_CTL_ADD, infd, &event);
        printf("epoll_ctl(...): %d \n", ret);
        if (ret == -1) {
          return -1;
        }
      } else {
        int bytes_read = read(events[i].data.fd, buffer, BUFFER_LEN);
        printf("read: fd: %d, bytes_read: %d \n", events[i].data.fd, bytes_read);
        if (bytes_read == -1) {
          if (errno != EAGAIN) {
            printf("errno: EAGAIN \n");
            close(events[i].data.fd);
          }
        } else if (bytes_read == 0) {
          printf("bytes_read == 0 \n");
          shutdown(events[i].data.fd, SHUT_RDWR);
          close(events[i].data.fd);
        } else {
          print_hex(buffer, bytes_read);
          write(events[i].data.fd, "ok\n", 4);
        }
      }
    }

    sleep(1);
  }

  return 0;
}

int proxy_stop(struct proxy_t* proxy) {
  return 0;
}

int proxy_add_rule(struct proxy_t* proxy, struct proxy_rule_t* rule) {
  proxy->_rule = *rule;
  printf("add_rule port_src: %d, ip_src: '%s', port_dst: %d, ip_dst: '%s' \n",
      rule->port_src, rule->ip_src, rule->port_dst, rule->ip_dst);
  return 0;
}

int proxy_set_nonblock(int fd) {
  int flags;
  flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    flags = 0;
  }

  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

////////////////////////////////////////////////////////////////////////////////

int main() {
  printf("start... \n");

  struct proxy_rule_t rule = {
    .port_src = 2468,
    .ip_src   = "127.0.0.1",
    .port_dst = 2470,
    .ip_dst   = "127.0.0.1",
  };

  struct proxy_t proxy;
  proxy_add_rule(&proxy, &rule);
  proxy_start(&proxy);
  proxy_stop(&proxy);

  printf("end... \n");
  return 0;
}


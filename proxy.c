
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <search.h>
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
  char    ip_src[16];
  int     port_dst;
  char    ip_dst[16];
};

int proxy_rule_print(struct proxy_rule_t* rule) {
  printf("rule: {%d, '%s', %d, '%s'} \n", rule->port_src, rule->ip_src, rule->port_dst, rule->ip_dst);
  return 0;
}

int proxy_rule_cmp(const void* p1, const void* p2) {
  struct proxy_rule_t* r1 = (struct proxy_rule_t*) p1;
  struct proxy_rule_t* r2 = (struct proxy_rule_t*) p2;
  int ret;

  ret = r1->port_src - r2->port_src;
  if (ret) return ret;

  ret = strcmp(r1->ip_src, r2->ip_src);
  if (ret) return ret;

  ret = r1->port_dst - r2->port_dst;
  if (ret) return ret;

  ret = strcmp(r1->ip_dst, r2->ip_dst);
  return ret;
}

struct proxy_rule_ext_t {
  struct proxy_rule_t   rule;
  int                   fd;
};

int proxy_rule_ext_cmp_fd(const void* p1, const void* p2) {
  struct proxy_rule_ext_t* r1 = (struct proxy_rule_ext_t*) p1;
  struct proxy_rule_ext_t* r2 = (struct proxy_rule_ext_t*) p2;
  return r1->fd - r2->fd;
}

struct proxy_fd_key_t {
  int   fd;
  int   fd_inv;
};

int proxy_fd_key_cmp(const void* p1, const void* p2) {
  struct proxy_fd_key_t* r1 = (struct proxy_fd_key_t*) p1;
  struct proxy_fd_key_t* r2 = (struct proxy_fd_key_t*) p2;
  return r1->fd - r2->fd;
}

////////////////////////////////////////////////////////////////////////////////

#define RULES_MAX_COUNT    100
#define FDS_MAX_COUNT      100000
#define EVENTS_MAX_COUNT   1024

struct proxy_t {
  struct proxy_rule_ext_t   _rules[RULES_MAX_COUNT];
  int                       _rules_count;

  struct proxy_fd_key_t     _fds[FDS_MAX_COUNT];
  int                       _fds_count;

  int                       _epfd;
  struct epoll_event        _events[EVENTS_MAX_COUNT];
};

int proxy_init(struct proxy_t* proxy);
int proxy_start(struct proxy_t* proxy);
int proxy_process(struct proxy_t* proxy);
int proxy_add_rule(struct proxy_t* proxy, struct proxy_rule_t* rule);
int proxy_create_server_socket(struct proxy_t* proxy, struct proxy_rule_ext_t* rule_ext);
int proxy_close_socket(struct proxy_t* proxy, int fd);
int proxy_set_nonblock(int fd);
int proxy_accept(struct proxy_t* proxy, struct proxy_rule_ext_t* rule_ext, int fd);

////////////////////////////////////////////////////////////////////////////////

int proxy_init(struct proxy_t* proxy) {
  proxy->_rules_count = 0;
  memset(proxy->_rules, 0, sizeof(proxy->_rules));

  proxy->_fds_count = 0;
  memset(proxy->_fds, 0, sizeof(proxy->_fds));

  return 0;
}

int proxy_create_server_socket(struct proxy_t* proxy, struct proxy_rule_ext_t* rule_ext) {
  int ret;
  struct proxy_rule_t* rule = &rule_ext->rule;

  rule_ext->fd = socket(AF_INET, SOCK_STREAM, 0);
  printf("rule_ext->fd: %d \n", rule_ext->fd);
  if (rule_ext->fd == -1) {
    return -1;
  }

  int on = 1;
  ret = setsockopt(rule_ext->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  printf("setsockopt(...): %d \n", ret);
  if (ret == -1) {
    return -1;
  }

  struct in_addr ip_src = {0};
  ret = inet_pton(AF_INET, rule->ip_src, &ip_src);
  printf("inet_pton(...): %d \n", ret);
  if (ret == -1) {
    return -1;
  }

  struct sockaddr_in addr;
  memset((char *) &addr, 0, sizeof(addr));
  addr.sin_family      = AF_INET;
  addr.sin_addr.s_addr = ip_src.s_addr;
  addr.sin_port        = htons(rule->port_src);

  ret = bind(rule_ext->fd, (struct sockaddr *) &addr, sizeof(addr));
  printf("bind(...): %d \n", ret);
  if (ret == -1) {
    return -1;
  }

  ret = proxy_set_nonblock(rule_ext->fd);
  printf("proxy_set_nonblock(...): %d \n", ret);
  if (ret == -1) {
    return -1;
  }

  ret = listen(rule_ext->fd, SOMAXCONN);
  printf("listen(...): %d \n", ret);
  if (ret == -1) {
    return -1;
  }

  struct epoll_event event;
  event.data.fd = rule_ext->fd;
  event.events = EPOLLIN;

  ret = epoll_ctl(proxy->_epfd, EPOLL_CTL_ADD, rule_ext->fd, &event);
  printf("epoll_ctl(...): %d \n", ret);
  if (ret == -1) {
    return -1;
  }

  return 0;
}

int proxy_start(struct proxy_t* proxy) {

  proxy->_epfd = epoll_create1(0);
  printf("proxy->_epfd: %d \n", proxy->_epfd);

  for (int i = 0; i < proxy->_rules_count; ++i) {
    int ret = proxy_create_server_socket(proxy, &proxy->_rules[i]);
    printf("proxy_create_server_socket(...): %d \n", ret);
  }

  return 0;
}

int proxy_process(struct proxy_t* proxy) {
  int event_count = epoll_wait(proxy->_epfd, proxy->_events, EVENTS_MAX_COUNT, -1);
  printf("event_count: %d \n", event_count);

  for (int i = 0; i < event_count; i++) {
    struct epoll_event* event = &proxy->_events[i];
    printf("events 0x%x \n", event->events);
    printf("fd: %d \n", event->data.fd);
    printf("_fds_count: %d \n", proxy->_fds_count);

    struct proxy_fd_key_t fd_key;
    fd_key.fd = event->data.fd;
    struct proxy_fd_key_t* fd_key_copy = bsearch(&fd_key, proxy->_fds, proxy->_fds_count,
        sizeof(proxy->_fds[0]), proxy_fd_key_cmp);

    if ((event->events & EPOLLERR) ||
        (event->events & EPOLLHUP) ||
        (!(event->events & EPOLLIN)))
    {
      printf("epoll error \n");
      if (fd_key_copy) {
        proxy_close_socket(proxy, fd_key_copy->fd_inv);
      }
      proxy_close_socket(proxy, event->data.fd);
      continue;
    }

    struct proxy_rule_ext_t rule_ext;
    rule_ext.fd = event->data.fd;
    size_t rules_count = proxy->_rules_count;
    void* rule = lfind(&rule_ext, proxy->_rules, &rules_count,
        sizeof(proxy->_rules[0]), proxy_rule_ext_cmp_fd);

    if (rule) {
      proxy_accept(proxy, rule, event->data.fd);
      continue;
    }

    {
      uint8_t buffer[1024];

      if (!fd_key_copy) {
        printf("!fd_key_copy \n");
        proxy_close_socket(proxy, event->data.fd);
        continue;
      }

      int bytes_read = read(event->data.fd, buffer, sizeof(buffer));
      printf("read: fd: %d, bytes_read: %d \n", event->data.fd, bytes_read);
      if (bytes_read == -1) {
        if (errno != EAGAIN) {
          printf("errno: !EAGAIN \n");
          proxy_close_socket(proxy, fd_key_copy->fd_inv);
          proxy_close_socket(proxy, event->data.fd);
        }
      } else if (bytes_read == 0) {
        printf("bytes_read == 0 \n");
        shutdown(event->data.fd, SHUT_RDWR);
        proxy_close_socket(proxy, fd_key_copy->fd_inv);
        proxy_close_socket(proxy, event->data.fd);
      } else {
        print_hex(buffer, bytes_read);
        write(fd_key_copy->fd_inv, buffer, bytes_read);
      }
    }
  }

  return 0;
}

int proxy_add_rule(struct proxy_t* proxy, struct proxy_rule_t* rule) {
  if (proxy->_rules_count >= RULES_MAX_COUNT) {
    printf("!_rules_count >= RULES_MAX_COUNT \n");
    return -1;
  }

  void* rule_copy = bsearch(rule, proxy->_rules, proxy->_rules_count, sizeof(proxy->_rules[0]), proxy_rule_cmp);
  if (rule_copy) {
    printf("!rule_copy \n");
    return -1;
  }

  proxy->_rules[proxy->_rules_count].rule = *rule;
  proxy->_rules_count++;
  qsort(proxy->_rules, proxy->_rules_count, sizeof(proxy->_rules[0]), proxy_rule_cmp);

  printf("rules: \n");
  for (int i = 0; i < proxy->_rules_count; ++i) {
    proxy_rule_print(&proxy->_rules[i].rule);
  }

  return 0;
}

int proxy_close_socket(struct proxy_t* proxy, int fd) { // XXX меняет proxy->_fds
  close(fd);

  if (proxy->_fds_count < 1) {
    printf("!_fds_count < 1 \n");
    return -1;
  }

  struct proxy_fd_key_t fd_key = {fd, -1};
  struct proxy_fd_key_t* fd_key_copy = bsearch(&fd_key, proxy->_fds, proxy->_fds_count,
      sizeof(proxy->_fds[0]), proxy_fd_key_cmp);

  if (fd_key_copy) {
    proxy->_fds_count--;
    *fd_key_copy = proxy->_fds[proxy->_fds_count];
    qsort(proxy->_fds, proxy->_fds_count, sizeof(proxy->_fds[0]), proxy_fd_key_cmp);
  }

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

int proxy_accept(struct proxy_t* proxy, struct proxy_rule_ext_t* rule_ext, int fd) {
  struct epoll_event event;
  int fd_src;
  int fd_dst;
  int ret;

  {
    fd_src = accept(fd , 0, 0);
    printf("fd_src: %d \n", fd_src);
    if (fd_src == -1) {
      return -1;
    }

    ret = proxy_set_nonblock(fd_src);
    printf("proxy_set_nonblock(...): %d \n", ret);
    if (ret == -1) {
      return -1;
    }

    event.data.fd = fd_src;
    event.events = EPOLLIN;
    ret = epoll_ctl(proxy->_epfd, EPOLL_CTL_ADD, fd_src, &event);
    printf("epoll_ctl(...): %d \n", ret);
    if (ret == -1) {
      return -1;
    }
  }

  {
    fd_dst = socket(AF_INET, SOCK_STREAM, 0);
    printf("fd_dst: %d \n", fd_dst);
    if (fd_dst == -1) {
      return -1;
    }

    int on = 1;
    ret = setsockopt(fd_dst, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    printf("setsockopt(...): %d \n", ret);
    if (ret == -1) {
      return -1;
    }

    struct in_addr ip_dst = {0};
    ret = inet_pton(AF_INET, rule_ext->rule.ip_dst, &ip_dst);
    printf("inet_pton(...): %d \n", ret);
    if (ret == -1) {
      return -1;
    }

    struct sockaddr_in addr;
    memset((char *) &addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = ip_dst.s_addr;
    addr.sin_port        = htons(rule_ext->rule.port_dst);

    ret = connect(fd_dst, (struct sockaddr *) &addr, sizeof(addr));
    printf("connect(...): %d \n", ret);
    if (ret == -1) {
      return -1;
    }

    event.data.fd = fd_dst;
    event.events = EPOLLIN;
    ret = epoll_ctl(proxy->_epfd, EPOLL_CTL_ADD, fd_dst, &event);
    printf("epoll_ctl(...): %d \n", ret);
    if (ret == -1) {
      return -1;
    }
  }

  if (proxy->_fds_count + 1 >= FDS_MAX_COUNT) { // _fds_count += 2
    printf("_fds_count + 1 >= FDS_MAX_COUNT \n");
    return -1;
  }

  proxy->_fds[proxy->_fds_count] = (struct proxy_fd_key_t) {fd_dst, fd_src};
  proxy->_fds_count++;
  proxy->_fds[proxy->_fds_count] = (struct proxy_fd_key_t) {fd_src, fd_dst};
  proxy->_fds_count++;
  qsort(proxy->_fds, proxy->_fds_count, sizeof(proxy->_fds[0]), proxy_fd_key_cmp);

  return 0;
}

////////////////////////////////////////////////////////////////////////////////

int main() {
  printf("start... \n");

  struct proxy_rule_t rule0 = { 2460, "127.0.0.1", 2470, "127.0.0.1", };
  struct proxy_rule_t rule1 = { 2461, "127.0.0.1", 2471, "127.0.0.1", };
  struct proxy_rule_t rule2 = { 2462, "127.0.0.1", 2472, "127.0.0.1", };

  struct proxy_t proxy;
  proxy_init(&proxy);
  proxy_add_rule(&proxy, &rule0);
  proxy_add_rule(&proxy, &rule1);
  proxy_add_rule(&proxy, &rule2);
  proxy_start(&proxy);
  while (!proxy_process(&proxy)) { }

  printf("end... \n");
  return 0;
}


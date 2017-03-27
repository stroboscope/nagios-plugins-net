#include "check_sockets.h"


int main(int argc, char ** argv)
{

  int sd;
  struct sockaddr_nl sa = {
    .nl_family = AF_NETLINK,
    .nl_pid    = 0,
  };

  int len    = 0;
  int rtalen = 0;
  int run    = 1;

  long udp_all = 0;

  char buf[SOCKET_BUFFER_SIZE];

  struct rtattr *attr;

  struct iovec iovr = { buf, sizeof(buf) };
  struct nlmsghdr *nhr;
  struct msghdr msgr = { &sa, sizeof(sa), &iovr, 1, NULL, 0, 0 };
  struct inet_diag_msg *diag_msg;

  if ( (sd = socket(AF_NETLINK,SOCK_RAW,NETLINK_INET_DIAG)) < 0 ) {
    perror("Cannot create socket.\n");
    exit(-1);
  }

  int retval = 0;
  struct inet_diag_req_v2 conn_req ;
  struct nlmsghdr nh ;
  struct iovec iov[4];
  struct msghdr msg ;

  conn_req.sdiag_family   = AF_INET;
  conn_req.sdiag_protocol = IPPROTO_UDP;
  conn_req.idiag_states   = -1;
  conn_req.idiag_ext      = 0;

  nh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
  nh.nlmsg_len   = NLMSG_LENGTH(sizeof(conn_req));
  nh.nlmsg_pid   = 0;
  nh.nlmsg_seq   = 654321;
  nh.nlmsg_type  = SOCK_DIAG_BY_FAMILY;

  iov[0].iov_base = (void*) &nh;
  iov[0].iov_len  = sizeof(nh);
  iov[1].iov_base = (void*) &conn_req;
  iov[1].iov_len  = sizeof(conn_req);

  msg.msg_name    = (void*) &sa;
  msg.msg_namelen = sizeof(sa);
  msg.msg_iov     = iov;
  msg.msg_iovlen  = 2;

  if ( (retval = sendmsg(sd, &msg, 0)) < 0) {
    close(sd);
    perror("Error sending message");
    exit(-1);
  }


  while(run) {
  
    len  = recvmsg(sd, &msgr, 0);
  
    if (len < 0 ){
      if (errno == EINTR)
        continue;
      perror("OVERRUN");
    }
  
    if (len == 0 ){
      close(sd);
      break;
    }

    if ( ! (nhr = (struct nlmsghdr *) buf))
      exit(-1);
    

    while (NLMSG_OK (nhr, len)) {
  
      if (nhr->nlmsg_seq != 654321) {
        continue;
      }

      if (nhr->nlmsg_type == NLMSG_ERROR) {
        close(sd);
        perror("Error on message receiving.\n");
        exit(-1);
      }
  
      if (nhr->nlmsg_type == NLMSG_DONE) {
        run = 0;
        break;
      }

      if (nhr->nlmsg_type != SOCK_DIAG_BY_FAMILY ) {
        close(sd);
        perror("Error: wrong message type.\n");
        exit(-1);
      }
  
      diag_msg = (struct inet_diag_msg*) NLMSG_DATA(nhr);
      rtalen = nhr->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));

      if(rtalen > 0){
        attr = (struct rtattr*) (diag_msg + 1);

        while(RTA_OK(attr, rtalen)){
          if(attr->rta_type == INET_DIAG_INFO){
        udp_all++;

          }
          attr = RTA_NEXT(attr, rtalen);

        }

      }

      if(rtalen == 0)
        udp_all++;
  
      nhr = NLMSG_NEXT (nhr, len);

    }

  }

  close(sd);

  printf("OK | udp: %ld", udp_all);

  exit(0);

}

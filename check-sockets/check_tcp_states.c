#include "check_sockets.h"

int main(int argc, char ** argv)
{

  int exit_code   = 0;
  int critical_tw = 20;
  int warn_tw     = 60;

  int sd;

  struct sockaddr_nl sa = {
    .nl_family = AF_NETLINK,
    .nl_pid    = 0,
  };

  int len    = 0;
  int rtalen = 0;
  int run    = 1;

  long tcp_est   = 0;
  long tcp_s_r   = 0;
  long tcp_s_s   = 0;
  long tcp_tw    = 0;
  long tcp_f_w1  = 0;
  long tcp_f_w2  = 0;
  long tcp_ln    = 0;
  long tcp_cls   = 0;
  long tcp_cls_w = 0;
  long tcp_clsng = 0;
  long tcp_l_ack = 0;
  long tcp_all   = 0;

  char buf[SOCKET_BUFFER_SIZE];

  struct rtattr *attr;
  struct tcp_info *tcpi;
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
  conn_req.sdiag_protocol = IPPROTO_TCP;

  conn_req.idiag_states = TCPF_ALL;
  conn_req.idiag_ext |= ( 1 << (INET_DIAG_INFO - 1) );

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

            tcpi = (struct tcp_info*) RTA_DATA(attr);

            if ( tcpi->tcpi_state == TCP_ESTABLISHED ) tcp_est++;
            if ( tcpi->tcpi_state == TCP_SYN_RECV )    tcp_s_r++;
            if ( tcpi->tcpi_state == TCP_SYN_SENT )    tcp_s_s++;
            if ( tcpi->tcpi_state == TCP_CLOSE )       tcp_cls++;
            if ( tcpi->tcpi_state == TCP_CLOSE_WAIT )  tcp_cls_w++;
            if ( tcpi->tcpi_state == TCP_FIN_WAIT1 )   tcp_f_w1++;
            if ( tcpi->tcpi_state == TCP_FIN_WAIT2 )   tcp_f_w2++;
            if ( tcpi->tcpi_state == TCP_LISTEN )      tcp_ln++;
            if ( tcpi->tcpi_state == TCP_CLOSING )     tcp_clsng++;
            if ( tcpi->tcpi_state == TCP_TIME_WAIT )   tcp_tw++;
            if ( tcpi->tcpi_state == TCP_LAST_ACK )    tcp_l_ack++;

          }
          attr = RTA_NEXT(attr, rtalen);

        }
      }

      if(rtalen == 0)
        tcp_all++;
  
      nhr = NLMSG_NEXT (nhr, len);

    }
  }

  close(sd);

  char fbuf[32] = {};
  long tw_sysctl = 0;

  FILE *fd = fopen(PROC_TW,"r");

  if ( fgets(fbuf,32,fd) == NULL ) {
    fclose(fd);
    perror("Error: can not read proc.\n");
    exit(-1);
  }

  fclose(fd);


  tw_sysctl = atol(fbuf);
  tcp_tw    = (long) (tcp_all
    - tcp_est   - tcp_s_r   - tcp_s_s
    - tcp_f_w1  - tcp_f_w2  - tcp_ln 
    - tcp_cls   - tcp_cls_w - tcp_clsng
    - tcp_l_ack);


  if ((( tw_sysctl - tcp_tw ) * 100 / tw_sysctl ) <= critical_tw ) {

    printf("ERROR : %ld time-wait, while configured max: %ld ",
      tcp_tw, tw_sysctl);

    exit_code = 3;

  } else if ((( tw_sysctl - tcp_tw ) * 100 / tw_sysctl ) <= warn_tw ) {

    printf("WARN : %ld time-wait, while configured max: %ld ",
      tcp_tw, tw_sysctl);

    exit_code = 2;

  } else {

    printf("OK : ");

  }

  printf(
    "%ld - established, "
    "%ld - time-wait "
    "| "
    "established=%ld "
    "syn-sent=%ld "
    "syn-recv=%ld "
    "time-wait=%ld "
    "close=%ld "
    "close-wait=%ld "
    "fin-wait1=%ld "
    "fin-wait2=%ld "
    "listen=%ld "
    "closing=%ld "
    "last-ack=%ld ",
    tcp_est,
    tcp_tw,
    tcp_est,
    tcp_s_s,
    tcp_s_r,
    tcp_tw,
    tcp_cls,
    tcp_cls_w,
    tcp_f_w1,
    tcp_f_w2,
    tcp_ln,
    tcp_clsng,
    tcp_l_ack
  );

  exit(exit_code);

}

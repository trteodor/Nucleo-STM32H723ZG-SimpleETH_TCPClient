
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <lwip/tcp.h>
#include "tcp_client.h"
#include "lwip/prot/dhcp.h"
#include "lwip/dhcp.h"
#include "lwip.h"

#define TIME_FRM "%Y.%m.%d %H:%M:%S"
#define PARAM_FRM "%"U32_F" %"U32_F
static const char ok_msg[]           = "OK";
static const char set_msg[]          = "SET";
static const char bye_msg[]          = "BYE";
static const char error_msg[]        = "ERROR";
//static const char hello_msg_frm[]    = "HELLO "TIME_FRM"\r\n";
static const char param_msg_frm[]    = "PARAM "PARAM_FRM"\r\n";
static const char ok_time_msg_frm[]  = "OK "TIME_FRM"\r\n";
static const char ok_param_msg_frm[] = "OK "PARAM_FRM"\r\n";
static const char bye_msg_frm[]      = "BYE "TIME_FRM"\r\n";
static const char error_msg_frm[]    = "ERROR "TIME_FRM"\r\n";
//static const char set_time_frm[]     = TIME_FRM;
static const char set_param_frm[]    = PARAM_FRM;

#define POLL_PER_SECOND             2
#define MSG_SIZE                    32
#define CONNECTION_TIMEOUT          0
#define STANDBY_TIME                1
#define PARAM_NUMBER                2
#define DEFAULT_CONNECTION_TIMEOUT  30
#define DEFAULT_STANDBY_TIME        20
#define MIN_CONNECTION_TIMEOUT      5
#define MAX_CONNECTION_TIMEOUT      600
#define MIN_STANDBY_TIME            1
#define MAX_STANDBY_TIME            1800

struct state {
  err_t (* function)(struct state *, struct tcp_pcb *);
  uint32_t param[PARAM_NUMBER];
  uint32_t timer;
  unsigned idx;
  char msg[MSG_SIZE];
};

static err_t connect_callback(void *, struct tcp_pcb *, err_t);
static err_t recv_callback(void *, struct tcp_pcb *,
                           struct pbuf *, err_t);
static err_t poll_callback(void *, struct tcp_pcb *);
static void  conn_err_callback(void *, err_t);
static err_t tcp_exit(struct state *, struct tcp_pcb *);
static err_t tcp_write_time_msg(struct tcp_pcb *, const char *);
static err_t tcp_write_param_msg(struct tcp_pcb *, struct state *,
                                 const char *);
static err_t StateAutomaton(struct state *, struct tcp_pcb *,
                            struct pbuf *);
static err_t HelloState(struct state *, struct tcp_pcb *);
static err_t ParamState(struct state *, struct tcp_pcb *);

/* W tej jednostce translacji tylko ta funkcja nie jest wołana
   w kontekście procedury obsługi przerwania. */

ip_addr_t DestIPaddr;
struct tcp_pcb *echoclient_pcb;
extern struct netif gnetif;


int TCPclientStart(uint16_t port) {
	  ip_addr_t DestIPaddr;

	  struct dhcp *dhcp;
	  dhcp = netif_dhcp_data(&gnetif);
	  while(dhcp->state != DHCP_STATE_BOUND ) //blokujaco do oporu az sie polaczy... XD
	  {						//a jak sie nie uda niech stoi i tak to tylko test...
		  MX_LWIP_Process ();  //wiadomo libka musi dzialac wczesniej se ja zblokowalem
		  	  	  	  	  //dobrze ze sie szybko kapnolem
	  }			//Ja nie wiem czego oni tego nie umieszcza np w przerwaniu od systicka :/
	  	  	  	  //tylko ze to tez moze byc zle moze lepiej timer z niskim priorytetem?
	  	  	  	  	  	  //no Najlepiej to RTOSik odzielny task i po zawodach
	  	  	  	  	  	  	  	  //Takie sa wady bare-metal

	  /* create new tcp pcb */
	  echoclient_pcb = tcp_new();

	  if (echoclient_pcb != NULL)
	  {
	    IP4_ADDR( &DestIPaddr, 192, 168, 0, 11 );

	    /* connect to destination address/port */
	    tcp_connect(echoclient_pcb,&DestIPaddr,7,connect_callback);
	  }
	  else
	  {
	    /* deallocate the pcb */
	    memp_free(MEMP_TCP_PCB, echoclient_pcb);
	  }

	  return 0;
}

err_t connect_callback(void *arg, struct tcp_pcb *pcb, err_t err) {
  /* Z analizy kodu wynika, że zawsze err == ERR_OK.
  if (err != ERR_OK)
    return err;
  */
	return tcp_write(pcb, "POZDRAWIAM\n\r", sizeof("POZDRAWIAM\n\r"), TCP_WRITE_FLAG_COPY);
 // return tcp_write_time_msg(pcb, hello_msg_frm);
}

#define ERR_EXIT 100

err_t recv_callback(void *arg, struct tcp_pcb *pcb,
                    struct pbuf *p, err_t err) {
  /* Z analizy kodu wynika, że zawsze err == ERR_OK.
  if (err != ERR_OK)
    return err;
  */
  if (p) {
    /* Odebrano dane. */
    tcp_recved(pcb, p->tot_len);
    err = StateAutomaton(arg, pcb, p);
    if (err == ERR_OK || err == ERR_EXIT)
      pbuf_free(p);
    if (err == ERR_EXIT) {
      err = tcp_exit(arg, pcb);
    }
  }
  else {
    /* Druga strona zamknęła połączenie. */
    err = tcp_exit(arg, pcb);
  }
  return err;
}

err_t poll_callback(void *arg, struct tcp_pcb *pcb) {
  struct state *state = arg;

  if (--(state->timer) <= 0) {
    tcp_write_time_msg(pcb, error_msg_frm);
    return tcp_exit(arg, pcb);
  }
  return ERR_OK;
}

void conn_err_callback(void *arg, err_t err) {
 // struct state *state = arg;

  /* TODO: Zapisać ustawienia do rejestrów zapasowych. */
  /* Nie musimy zwalniać pamięci, bo i tak resetujemy. Przed
     zaśnieciem należy poczekać na zakończenie transmisji. */
  //DelayedStandby(2, state->param[STANDBY_TIME]);
}

err_t tcp_exit(struct state *state, struct tcp_pcb *pcb) {
  /* Nie musimy zwalniać pamięci, bo i tak resetujemy. */
  if (tcp_close(pcb) != ERR_OK) {
    /* Funkcja tcp_abort woła funkcję conn_err_callback. */
    tcp_abort(pcb);
    return ERR_ABRT;
  }
  else {
    /* TODO: Zapisać ustawienia do rejestrów zapasowych. */
  //  DelayedStandby(2, state->param[STANDBY_TIME]);
    return ERR_OK;
  }
}

err_t tcp_write_time_msg(struct tcp_pcb *pcb, const char *format) {
  char msg[MSG_SIZE];
  //time_t rtime;
  struct tm tm;
  size_t size;


 // rtime = GetRealTimeClock();
 // if (localtime_r(&rtime, &tm) == NULL)
  //  return ERR_OK; /* Nic rozsądnego nie można zrobić. */
  /* Zabroń współużywania funkcji niewspółużywalnej. */

  size = strftime(msg, MSG_SIZE, format, &tm);

  return tcp_write(pcb, msg, size, TCP_WRITE_FLAG_COPY);
}

err_t tcp_write_param_msg(struct tcp_pcb *pcb, struct state *s,
                          const char *format) {
  char msg[MSG_SIZE];
  size_t size;



  size = snprintf(msg, MSG_SIZE, format,
                  s->param[CONNECTION_TIMEOUT],
                  s->param[STANDBY_TIME]);

  if (size >= MSG_SIZE)
    size = MSG_SIZE - 1;
  return tcp_write(pcb, msg, size, TCP_WRITE_FLAG_COPY);
}

err_t StateAutomaton(struct state *s, struct tcp_pcb *pcb,
                     struct pbuf *p) {
  s->timer = s->param[CONNECTION_TIMEOUT];
  for (;;) {
    uint8_t *c = (uint8_t *)p->payload;
    uint16_t i;
    err_t err;

    for (i = 0; i < p->len; ++i) {
      if (c[i] == '\n') {
        s->msg[s->idx++] = c[i];
        s->msg[s->idx] = '\0';
        s->idx = 0;
        err = s->function(s, pcb);
        if (err != ERR_OK)
          return err;
      }
      /* Muszą się jeszcze zmieścić dwa znaki: '\n' i '\0'. */
      else if (s->idx < MSG_SIZE - 2)
        s->msg[s->idx++] = c[i];
    }
    if (p->len == p->tot_len)
      break;
    else
      p = p->next;
  }
  return ERR_OK;
}

#define msglen(s) (sizeof(s) - 1)
#define msgncmp(s1, s2, n) \
  (strncmp(s1, s2, n) == 0 && isspace((int)s1[n]))

err_t HelloState(struct state *state, struct tcp_pcb *pcb) {
  if (msgncmp(state->msg, ok_msg, msglen(ok_msg))) {
    state->function = ParamState;
    return tcp_write_param_msg(pcb, state, param_msg_frm);
  }
  else if (msgncmp(state->msg, set_msg, msglen(set_msg))) {
    err_t err;
    time_t t;
    struct tm tm;

  /*  if (!strptime(state->msg + msglen(set_msg), set_time_frm, &tm)) {
      tcp_write_time_msg(pcb, error_msg_frm);
      return ERR_EXIT;
    }*/
    t = mktime(&tm);
    if (t == (time_t)-1) {
      tcp_write_time_msg(pcb, error_msg_frm);
      return ERR_EXIT;
    }
  //  SetRealTimeClock(t);
    err = tcp_write_time_msg(pcb, ok_time_msg_frm);
    if (err != ERR_OK)
      return err;
    state->function = ParamState;
    return tcp_write_param_msg(pcb, state, param_msg_frm);
  }
  else if (msgncmp(state->msg, bye_msg, msglen(bye_msg)) ||
           msgncmp(state->msg, error_msg, msglen(error_msg)))
    return ERR_EXIT;
  else {
    tcp_write_time_msg(pcb, error_msg_frm);
    return ERR_EXIT;
  }
}

err_t ParamState(struct state *state, struct tcp_pcb *pcb) {
  if (msgncmp(state->msg, ok_msg, msglen(ok_msg))) {
    tcp_write_time_msg(pcb, bye_msg_frm);
  }
  else if (msgncmp(state->msg, set_msg, msglen(set_msg))) {
    uint32_t timeout, sleep_time;
    int ret;


    /* Zabroń współużywania funkcji niewspółużywalnej. */

    ret = sscanf(state->msg + msglen(set_msg), set_param_frm,
                 &timeout, &sleep_time);

    if (ret != 2 ||
        timeout < MIN_CONNECTION_TIMEOUT ||
        timeout > MAX_CONNECTION_TIMEOUT ||
        sleep_time < MIN_STANDBY_TIME ||
        sleep_time > MAX_STANDBY_TIME) {
      tcp_write_time_msg(pcb, error_msg_frm);
    }
    else {
      state->param[CONNECTION_TIMEOUT] = timeout;
      state->param[STANDBY_TIME] = sleep_time;
      tcp_write_param_msg(pcb, state, ok_param_msg_frm);
      tcp_write_time_msg(pcb, bye_msg_frm);
    }
  }
  else if (!msgncmp(state->msg, bye_msg, msglen(bye_msg)) &&
           !msgncmp(state->msg, error_msg, msglen(error_msg)))
    tcp_write_time_msg(pcb, error_msg_frm);
  return ERR_EXIT;
}
